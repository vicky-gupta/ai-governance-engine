// Package policy evaluates the governance rules written in Rego (Open
// Policy Agent's language) in the policies/ folder. Rules live in files,
// not Go code: they can be reviewed like code, tested on their own, and
// changed without rebuilding or restarting the gateway.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Result is what the policy decided for one request.
type Result struct {
	Deny      []string // reasons to block
	Hold      []string // reasons to pause for human review
	MaxTokens *int     // limit for max_tokens; nil if the policy sets none
}

// ToolResult is what the policy decided about the tool calls in one
// model response.
type ToolResult struct {
	Deny []string // reasons to stop the response
	Hold []string // reasons to pause it for human review
}

// ResponseResult is what the policy decided about the text of one model
// answer.
type ResponseResult struct {
	Deny []string // reasons to stop the answer
}

// compiled is one loaded version of the policy files.
type compiled struct {
	query         rego.PreparedEvalQuery // data.aigov: rules for requests
	toolQuery     rego.PreparedEvalQuery // data.aigov.tool_calls: rules for tool calls
	responseQuery rego.PreparedEvalQuery // data.aigov.response: rules for answer text
	version       string
}

// Engine holds the active policy and swaps in new versions safely.
type Engine struct {
	dir        string
	log        *slog.Logger
	current    atomic.Pointer[compiled]
	lastFailed string // version that failed to compile, to log it once
}

// evalTimeout stops a slow or looping policy from holding up a request.
const evalTimeout = 250 * time.Millisecond

// Load compiles the policies in dir. Startup fails if they don't compile:
// the gateway never runs without a valid policy.
func Load(ctx context.Context, dir string, log *slog.Logger) (*Engine, error) {
	e := &Engine{dir: dir, log: log}
	files, version, err := readPolicies(dir)
	if err != nil {
		return nil, err
	}
	c, err := compile(ctx, files, version)
	if err != nil {
		return nil, err
	}
	e.current.Store(c)
	return e, nil
}

// Version identifies the active policy files (a short content hash).
func (e *Engine) Version() string {
	return e.current.Load().version
}

// Evaluate runs the active policy on input. It returns the result and the
// version of the policy that produced it.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) (Result, string, error) {
	c := e.current.Load() // one version for the whole evaluation
	out, err := eval(ctx, c.query, input)
	if err != nil {
		return Result{}, c.version, fmt.Errorf("%w (is the package named aigov?)", err)
	}

	res := Result{Deny: toStrings(out["deny"]), Hold: toStrings(out["hold"])}
	if v, ok := out["max_tokens"]; ok {
		n, ok := v.(json.Number)
		i, err := n.Int64()
		if !ok || err != nil || i <= 0 {
			return Result{}, c.version, fmt.Errorf("policy: max_tokens must be a positive whole number, got %v", v)
		}
		limit := int(i)
		res.MaxTokens = &limit
	}
	return res, c.version, nil
}

// EvaluateToolCalls runs the tool-call rules (package aigov.tool_calls)
// on the tool calls in a model response.
func (e *Engine) EvaluateToolCalls(ctx context.Context, input map[string]any) (ToolResult, string, error) {
	c := e.current.Load()
	out, err := eval(ctx, c.toolQuery, input)
	if err != nil {
		return ToolResult{}, c.version, fmt.Errorf("%w (is there a package aigov.tool_calls?)", err)
	}
	return ToolResult{Deny: toStrings(out["deny"]), Hold: toStrings(out["hold"])}, c.version, nil
}

// EvaluateResponse runs the answer rules (package aigov.response) on the
// text of a model answer.
func (e *Engine) EvaluateResponse(ctx context.Context, input map[string]any) (ResponseResult, string, error) {
	c := e.current.Load()
	out, err := eval(ctx, c.responseQuery, input)
	if err != nil {
		return ResponseResult{}, c.version, fmt.Errorf("%w (is there a package aigov.response?)", err)
	}
	return ResponseResult{Deny: toStrings(out["deny"])}, c.version, nil
}

// eval runs one prepared query with a time limit and returns the package
// it evaluates to as a map.
func eval(ctx context.Context, q rego.PreparedEvalQuery, input map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, evalTimeout)
	defer cancel()

	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("policy: no result")
	}
	out, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, errors.New("policy: unexpected result type")
	}
	return out, nil
}

// Watch checks the policy folder every interval and loads changed files.
// It returns when ctx is cancelled.
func (e *Engine) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.reload(ctx)
		}
	}
}

// reload loads the files if they changed. A version that doesn't compile
// is rejected and the previous one stays active.
func (e *Engine) reload(ctx context.Context) {
	files, version, err := readPolicies(e.dir)
	if err != nil {
		e.log.Error("policy: cannot read policy files", "error", err)
		return
	}
	if version == e.Version() || version == e.lastFailed {
		return
	}
	c, err := compile(ctx, files, version)
	if err != nil {
		e.lastFailed = version
		e.log.Error("policy: new version rejected, previous version still active",
			"rejected", version, "active", e.Version(), "error", err)
		return
	}
	old := e.Version()
	e.current.Store(c)
	e.log.Info("policy: new version active", "version", version, "previous", old)
}

// readPolicies reads every .rego file in dir except tests, and returns
// them with a version: a hash of their names and contents.
func readPolicies(dir string) (map[string]string, string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil {
		return nil, "", err
	}
	sort.Strings(paths)
	files := map[string]string{}
	h := sha256.New()
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.rego") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, "", err
		}
		name := filepath.Base(p)
		files[name] = string(b)
		fmt.Fprintf(h, "%s\x00%s\x00", name, b)
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("policy: no .rego files in %s", dir)
	}
	return files, hex.EncodeToString(h.Sum(nil))[:12], nil
}

func compile(ctx context.Context, files map[string]string, version string) (*compiled, error) {
	q, err := prepare(ctx, files, "data.aigov")
	if err != nil {
		return nil, err
	}
	tq, err := prepare(ctx, files, "data.aigov.tool_calls")
	if err != nil {
		return nil, err
	}
	rq, err := prepare(ctx, files, "data.aigov.response")
	if err != nil {
		return nil, err
	}
	return &compiled{query: q, toolQuery: tq, responseQuery: rq, version: version}, nil
}

func prepare(ctx context.Context, files map[string]string, query string) (rego.PreparedEvalQuery, error) {
	opts := []func(*rego.Rego){rego.Query(query)}
	for name, src := range files {
		opts = append(opts, rego.Module(name, src))
	}
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("policy: %w", err)
	}
	return q, nil
}

// toStrings turns a Rego set (which arrives as a list) into sorted strings.
func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
