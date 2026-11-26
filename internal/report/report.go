// Package report builds compliance evidence reports: for one AI system
// and one period, what the gateway decided, what personal data it kept
// from the models, where requests were processed, where people reviewed
// decisions, and whether the audit log is intact.
//
// A report is evidence for an assessment, not the assessment itself. It
// reads several tables directly: it is a read model, so it doesn't go
// through each store's write API.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
)

// ErrNotFound means there is no AI system with that ID.
var ErrNotFound = errors.New("AI system not found")

// Report is one compliance evidence report.
type Report struct {
	GeneratedAt    time.Time    `json:"generated_at"`
	From           time.Time    `json:"from"`
	To             time.Time    `json:"to"`
	System         System       `json:"ai_system"`
	Requests       Requests     `json:"requests"`
	PersonalData   PersonalData `json:"personal_data"`
	Routing        []Route      `json:"routing"`
	Answers        Answers      `json:"answers"`
	Oversight      Oversight    `json:"human_oversight"`
	Usage          Usage        `json:"usage"`
	PolicyVersions []string     `json:"policy_versions"`
	Integrity      Integrity    `json:"integrity"`
	Evidence       []Evidence   `json:"evidence"`
	Disclaimer     string       `json:"disclaimer"`

	// Hash is the SHA-256 of this report with Hash left empty. It is
	// recorded in the audit log, so a saved copy can be checked later.
	Hash string `json:"hash"`
}

type System struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	Purpose  string `json:"purpose"`
	RiskTier string `json:"risk_tier"`
	Status   string `json:"status"`
}

// Requests counts the gateway's decision on each request.
type Requests struct {
	Total      int            `json:"total"`
	ByDecision map[string]int `json:"by_decision"`
	StoppedBy  []Count        `json:"stopped_by"`  // which check blocked or held them
	TopReasons []Count        `json:"top_reasons"` // the most common reasons for stopping
}

type PersonalData struct {
	RequestsRedacted int            `json:"requests_with_redactions"`
	ByKind           map[string]int `json:"values_by_kind"`
}

// Route is where forwarded requests went.
type Route struct {
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Requests int    `json:"requests"`
}

// Answers counts the checks on what came back.
type Answers struct {
	ToolCalls map[string]int `json:"tool_calls"` // allow / hold / block
	Text      map[string]int `json:"text"`       // modify (redacted) / block / flag
}

type Oversight struct {
	Approvals       []Count         `json:"approvals"` // e.g. "request: approved"
	MedianToDecide  string          `json:"median_time_to_decision,omitempty"`
	Reviewers       []ReviewerCount `json:"reviewers"`
	DecisionsLogged int             `json:"decisions_in_audit_log"`
}

type ReviewerCount struct {
	Name     string `json:"name"`
	Approved int    `json:"approved"`
	Rejected int    `json:"rejected"`
}

type Usage struct {
	TotalTokens int64        `json:"total_tokens"`
	Budget      *int64       `json:"monthly_token_budget"`
	ByModel     []ModelUsage `json:"by_model"`
}

type ModelUsage struct {
	Model    string `json:"model"`
	Requests int64  `json:"requests"`
	Tokens   int64  `json:"tokens"`
}

// Integrity is the state of the whole audit log when the report was made.
type Integrity struct {
	ChainOK       bool   `json:"chain_ok"`
	Checked       int    `json:"entries_checked"`
	Problem       string `json:"problem,omitempty"`
	HeadID        int64  `json:"chain_head_id"`
	HeadHash      string `json:"chain_head_hash"`
	SystemEntries int    `json:"entries_for_this_system"`
}

// Evidence says which article a section of the report supports.
type Evidence struct {
	Regulation string `json:"regulation"`
	Article    string `json:"article"`
	Topic      string `json:"topic"`
	Section    string `json:"see"`
}

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Verifier checks the audit chain. audit.Store implements it.
type Verifier interface {
	Verify(ctx context.Context) (audit.VerifyResult, error)
}

// Builder makes reports.
type Builder struct {
	pool  *pgxpool.Pool
	chain Verifier
	now   func() time.Time
}

func NewBuilder(pool *pgxpool.Pool, chain Verifier) *Builder {
	return &Builder{pool: pool, chain: chain, now: time.Now}
}

// Build makes the report for one AI system, for [from, to).
func (b *Builder) Build(ctx context.Context, systemID string, from, to time.Time) (Report, error) {
	r := Report{
		GeneratedAt: b.now().UTC().Truncate(time.Second),
		From:        from.UTC(),
		To:          to.UTC(),
		Evidence:    evidence,
		Disclaimer: "This report is evidence to support a compliance assessment. " +
			"It is not legal advice and not a conformity assessment.",
	}
	steps := []func(context.Context, string, *Report) error{
		b.system, b.decisions, b.oversight, b.usage, b.integrity,
	}
	for _, step := range steps {
		if err := step(ctx, systemID, &r); err != nil {
			return Report{}, err
		}
	}
	return r, nil
}

func (b *Builder) system(ctx context.Context, id string, r *Report) error {
	err := b.pool.QueryRow(ctx, `
		SELECT id::text, name, owner, purpose, risk_tier, status FROM ai_systems WHERE id = $1`, id,
	).Scan(&r.System.ID, &r.System.Name, &r.System.Owner, &r.System.Purpose, &r.System.RiskTier, &r.System.Status)
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "22P02") {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("report: system: %w", err)
	}
	return nil
}

// decisions goes through the system's audit entries in the period once,
// and sorts each into its section.
func (b *Builder) decisions(ctx context.Context, id string, r *Report) error {
	rows, err := b.pool.Query(ctx, `
		SELECT action, check_name, reason, model, provider, region, policy_version, trace
		FROM audit_log
		WHERE ai_system_id = $1 AND created_at >= $2 AND created_at < $3
		ORDER BY id`, id, r.From, r.To)
	if err != nil {
		return fmt.Errorf("report: audit log: %w", err)
	}
	defer rows.Close()

	r.Requests.ByDecision = map[string]int{}
	r.PersonalData.ByKind = map[string]int{}
	r.Answers.ToolCalls = map[string]int{}
	r.Answers.Text = map[string]int{}
	stopped, reasons := map[string]int{}, map[string]int{}
	routes := map[Route]int{}
	versions := map[string]bool{}

	for rows.Next() {
		var action, check, reason, model, provider, region, version string
		var trace []byte
		if err := rows.Scan(&action, &check, &reason, &model, &provider, &region, &version, &trace); err != nil {
			return fmt.Errorf("report: audit log: %w", err)
		}
		r.Integrity.SystemEntries++
		if version != "" {
			versions[version] = true
		}

		switch {
		case check == "tool_calls":
			r.Answers.ToolCalls[action]++
		case check == "response":
			r.Answers.Text[action]++
		case action == "approve" || action == "reject":
			r.Oversight.DecisionsLogged++
		case strings.HasPrefix(action, "admin."):
			// e.g. this system's earlier reports: not a request
		default:
			// The gateway's decision on one request.
			r.Requests.Total++
			r.Requests.ByDecision[action]++
			switch action {
			case "block", "hold":
				stopped[check+": "+action]++
				reasons[withoutApproval(reason)]++
			case "allow", "modify":
				routes[Route{Model: model, Provider: provider, Region: region}]++
			}
			if n := redactions(trace, r.PersonalData.ByKind); n > 0 {
				r.PersonalData.RequestsRedacted++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("report: audit log: %w", err)
	}

	r.Requests.StoppedBy = sorted(stopped, 0)
	r.Requests.TopReasons = sorted(reasons, 5)
	for route, n := range routes {
		route.Requests = n
		r.Routing = append(r.Routing, route)
	}
	sort.Slice(r.Routing, func(i, j int) bool { return r.Routing[i].Requests > r.Routing[j].Requests })
	r.PolicyVersions = keys(versions)
	return nil
}

// withoutApproval drops the approval reference the gateway adds to a
// held request's reason ("... (approval 2f85...)"), so the same reason
// counts as one, whichever approval it opened.
func withoutApproval(reason string) string {
	if i := strings.Index(reason, " (approval "); i >= 0 {
		return reason[:i]
	}
	return reason
}

// redactions adds up what the PII check redacted in one request, from its
// trace ("redacted 1 EMAIL, 2 PERSON"), and returns how many values.
func redactions(trace []byte, byKind map[string]int) int {
	var steps []pipeline.Step
	if json.Unmarshal(trace, &steps) != nil {
		return 0
	}
	total := 0
	for _, s := range steps {
		if s.Check != "pii_redaction" || s.Action != pipeline.Modify {
			continue
		}
		for kind, n := range ParseSummary(s.Reason) {
			byKind[kind] += n
			total += n
		}
	}
	return total
}

// ParseSummary reads the PII check's reason, "redacted 1 EMAIL, 2 PERSON",
// back into counts per kind.
func ParseSummary(reason string) map[string]int {
	out := map[string]int{}
	list, ok := strings.CutPrefix(reason, "redacted ")
	if !ok {
		return out
	}
	for _, part := range strings.Split(list, ", ") {
		num, kind, ok := strings.Cut(part, " ")
		if n, err := strconv.Atoi(num); ok && err == nil && kind != "" {
			out[kind] += n
		}
	}
	return out
}

// oversight reads the approvals opened for this system in the period.
func (b *Builder) oversight(ctx context.Context, id string, r *Report) error {
	rows, err := b.pool.Query(ctx, `
		SELECT a.kind, a.status, a.expires_at <= now() AND a.status IN ('pending', 'approved'),
			COALESCE(r.name, ''), EXTRACT(EPOCH FROM a.decided_at - a.created_at)::float8
		FROM approvals a LEFT JOIN reviewers r ON r.id = a.decided_by
		WHERE a.ai_system_id = $1 AND a.created_at >= $2 AND a.created_at < $3`,
		id, r.From, r.To)
	if err != nil {
		return fmt.Errorf("report: approvals: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	reviewers := map[string]*ReviewerCount{}
	var waits []time.Duration
	for rows.Next() {
		var kind, status, reviewer string
		var expired bool
		var wait *float64 // seconds; NULL while undecided
		if err := rows.Scan(&kind, &status, &expired, &reviewer, &wait); err != nil {
			return fmt.Errorf("report: approvals: %w", err)
		}
		if expired {
			status = "expired"
		}
		counts[kind+": "+status]++
		if wait != nil {
			waits = append(waits, time.Duration(*wait*float64(time.Second)))
		}
		if reviewer == "" {
			continue
		}
		rc := reviewers[reviewer]
		if rc == nil {
			rc = &ReviewerCount{Name: reviewer}
			reviewers[reviewer] = rc
		}
		if status == "rejected" {
			rc.Rejected++
		} else {
			rc.Approved++ // approved, or approved and since used or expired
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("report: approvals: %w", err)
	}

	r.Oversight.Approvals = sorted(counts, 0)
	if len(waits) > 0 {
		sort.Slice(waits, func(i, j int) bool { return waits[i] < waits[j] })
		r.Oversight.MedianToDecide = waits[len(waits)/2].Round(time.Second).String()
	}
	for _, rc := range reviewers {
		r.Oversight.Reviewers = append(r.Oversight.Reviewers, *rc)
	}
	sort.Slice(r.Oversight.Reviewers, func(i, j int) bool { return r.Oversight.Reviewers[i].Name < r.Oversight.Reviewers[j].Name })
	return nil
}

func (b *Builder) usage(ctx context.Context, id string, r *Report) error {
	if err := b.pool.QueryRow(ctx, "SELECT monthly_token_budget FROM ai_systems WHERE id = $1", id).
		Scan(&r.Usage.Budget); err != nil {
		return fmt.Errorf("report: budget: %w", err)
	}
	rows, err := b.pool.Query(ctx, `
		SELECT model, count(*), COALESCE(sum(total_tokens), 0)::bigint FROM usage_records
		WHERE ai_system_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY model ORDER BY 3 DESC`, id, r.From, r.To)
	if err != nil {
		return fmt.Errorf("report: usage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m ModelUsage
		if err := rows.Scan(&m.Model, &m.Requests, &m.Tokens); err != nil {
			return fmt.Errorf("report: usage: %w", err)
		}
		r.Usage.ByModel = append(r.Usage.ByModel, m)
		r.Usage.TotalTokens += m.Tokens
	}
	return rows.Err()
}

// integrity checks the whole audit chain and notes its latest entry: the
// report describes the log as it was up to that entry.
func (b *Builder) integrity(ctx context.Context, _ string, r *Report) error {
	v, err := b.chain.Verify(ctx)
	if err != nil {
		return fmt.Errorf("report: verify: %w", err)
	}
	r.Integrity.ChainOK, r.Integrity.Checked, r.Integrity.Problem = v.OK, v.Checked, v.Problem
	err = b.pool.QueryRow(ctx, "SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").
		Scan(&r.Integrity.HeadID, &r.Integrity.HeadHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("report: chain head: %w", err)
	}
	return nil
}

// Seal sets r.Hash: the SHA-256 of the report's JSON with Hash empty.
// encoding/json writes struct fields in order and map keys sorted, so the
// same report always gives the same bytes and the same hash.
func Seal(r *Report) error {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	r.Hash = hex.EncodeToString(h[:])
	return nil
}

// Intact reports whether a report (for example, a saved copy) still
// matches its own hash.
func Intact(r Report) bool {
	want := r.Hash
	if err := Seal(&r); err != nil {
		return false
	}
	return r.Hash == want
}

func sorted(m map[string]int, limit int) []Count {
	out := make([]Count, 0, len(m))
	for name, n := range m {
		out = append(out, Count{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// evidence maps the report's sections to the articles they support.
var evidence = []Evidence{
	{"EU AI Act", "Art. 12", "Automatic recording of events (logs)", "integrity, requests"},
	{"EU AI Act", "Art. 14", "Human oversight", "human_oversight"},
	{"EU AI Act", "Art. 26", "Deployer monitoring and keeping logs", "requests, answers, integrity"},
	{"GDPR", "Art. 5(1)(c)", "Data minimisation", "personal_data"},
	{"GDPR", "Art. 22", "Automated decisions with human involvement", "human_oversight"},
	{"GDPR", "Art. 30", "Records of processing: purpose, recipients", "ai_system, routing"},
	{"GDPR", "Art. 44-49", "Transfers outside the EU", "routing (region)"},
}

// Recorded reports whether a report with this hash was issued, that is,
// recorded in the audit log.
func (b *Builder) Recorded(ctx context.Context, hash string) (bool, error) {
	var found bool
	err := b.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'admin.report' AND reason LIKE '%sha256:' || $1)`,
		hash).Scan(&found)
	return found, err
}
