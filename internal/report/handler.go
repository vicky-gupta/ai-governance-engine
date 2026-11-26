package report

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
)

//go:embed report.html
var page string

// html/template escapes everything it inserts: system names, purposes
// and policy reasons all come from people, and a report must not become
// a way to run script in an auditor's browser.
var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"date": func(t time.Time) string { return t.Format("2006-01-02") },
}).Parse(page))

// Recorder writes audit entries. audit.Store implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

type handler struct {
	b   *Builder
	rec Recorder
	log *slog.Logger
}

// Handler serves reports under /admin/reports. It must be wrapped in the
// admin token check.
//
//	GET  /admin/reports/systems/{id}?from=2026-11-01&to=2026-12-01&format=html
//	POST /admin/reports/verify   (body: a report in JSON)
func Handler(b *Builder, rec Recorder, log *slog.Logger) http.Handler {
	h := &handler{b: b, rec: rec, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/reports/systems/{id}", h.report)
	mux.HandleFunc("POST /admin/reports/verify", h.verify)
	return mux
}

func (h *handler) report(w http.ResponseWriter, r *http.Request) {
	from, to, err := period(r, h.b.now())
	if err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "html" {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "format must be json or html")
		return
	}

	rep, err := h.b.Build(r.Context(), r.PathValue("id"), from, to)
	if errors.Is(err, ErrNotFound) {
		apierr.Write(w, http.StatusNotFound, "invalid_request_error", err.Error())
		return
	}
	if err == nil {
		err = Seal(&rep)
	}
	if err != nil {
		h.log.Error("report failed", "error", err)
		apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
		return
	}

	// Anchor the report in the audit log. A report that isn't recorded
	// can't be checked later, so it isn't handed out.
	err = h.rec.Record(r.Context(), audit.Entry{
		RequestID:  newID(),
		SystemID:   rep.System.ID,
		SystemName: rep.System.Name,
		Action:     "admin.report",
		Reason:     "evidence report " + rep.From.Format("2006-01-02") + " to " + rep.To.Format("2006-01-02") + ": sha256:" + rep.Hash,
	})
	if err != nil {
		h.log.Error("report not recorded in the audit log", "error", err)
		apierr.Write(w, http.StatusServiceUnavailable, "gateway_error", "audit log unavailable; report not issued")
		return
	}

	if format == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, rep); err != nil {
			h.log.Error("report page failed", "error", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

// verify checks a saved report: unchanged since it was made, and
// recorded in the audit log.
func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	var rep Report
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rep); err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "body must be a report in JSON")
		return
	}
	intact := Intact(rep)
	recorded := false
	if intact {
		var err error
		if recorded, err = h.b.Recorded(r.Context(), rep.Hash); err != nil {
			h.log.Error("report verify failed", "error", err)
			apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"intact": intact, "recorded": recorded})
}

// period reads ?from= and ?to= (dates, UTC; to is exclusive). The
// default is the current month so far.
func period(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	now = now.UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := now
	var err error
	if s := r.URL.Query().Get("from"); s != "" {
		if from, err = time.Parse("2006-01-02", s); err != nil {
			return time.Time{}, time.Time{}, errors.New("from must be a date like 2026-11-01")
		}
	}
	if s := r.URL.Query().Get("to"); s != "" {
		if to, err = time.Parse("2006-01-02", s); err != nil {
			return time.Time{}, time.Time{}, errors.New("to must be a date like 2026-12-01")
		}
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	return from, to, nil
}

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
