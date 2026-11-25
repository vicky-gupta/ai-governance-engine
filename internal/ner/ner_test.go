package ner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

// sidecar is a fake NER service that finds the given names, counting in
// characters like the real one (Python) does.
func sidecar(t *testing.T, names ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Text string }
		json.NewDecoder(r.Body).Decode(&req)
		var ents []entity
		for _, n := range names {
			if i := strings.Index(req.Text, n); i >= 0 {
				start := utf8.RuneCountInString(req.Text[:i]) // characters, not bytes
				ents = append(ents, entity{Type: "PERSON", Start: start, End: start + utf8.RuneCountInString(n), Score: 0.85})
			}
		}
		ents = append(ents, entity{Type: "ORGANIZATION", Start: 0, End: 1}) // not ours: ignored
		json.NewEncoder(w).Encode(map[string]any{"language": "de", "entities": ents})
	}))
}

func TestOffsetsAreConvertedToBytes(t *testing.T) {
	srv := sidecar(t, "Jürgen Müller")
	defer srv.Close()

	// Umlauts and an emoji before the name move its byte position, but
	// not its character position.
	text := "Grüße 👋 an Jürgen Müller, bitte prüfen."
	got, err := New(srv.URL, time.Second).Detect(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != pii.Person || got[0].Value != "Jürgen Müller" {
		t.Fatalf("Detect = %+v, want exactly the name", got)
	}
	if text[got[0].Start:got[0].End] != "Jürgen Müller" {
		t.Errorf("byte offsets %d-%d point at %q", got[0].Start, got[0].End, text[got[0].Start:got[0].End])
	}
}

func TestErrors(t *testing.T) {
	down := New("http://127.0.0.1:1", 200*time.Millisecond)
	if _, err := down.Detect(context.Background(), "Jürgen Müller"); err == nil {
		t.Error("unreachable sidecar: want an error")
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"model not loaded"}`, http.StatusInternalServerError)
	}))
	defer broken.Close()
	if _, err := New(broken.URL, time.Second).Detect(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("sidecar error: %v", err)
	}

	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"entities": []entity{{Type: "PERSON", Start: 2, End: 999}}})
	}))
	defer wrong.Close()
	if _, err := New(wrong.URL, time.Second).Detect(context.Background(), "short"); err == nil {
		t.Error("offsets past the end of the text: want an error, not a panic")
	}
}

func TestEmptyTextIsNotSent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	if got, err := New(srv.URL, time.Second).Detect(context.Background(), "   "); err != nil || got != nil || called {
		t.Errorf("got %v, %v, called=%v", got, err, called)
	}
}

func TestPlacesOnlyCountNextToAPerson(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Text string }
		json.NewDecoder(r.Body).Decode(&req)
		ents := []entity{}
		if i := strings.Index(req.Text, "France"); i >= 0 {
			ents = append(ents, entity{Type: "LOCATION", Start: i, End: i + 6})
		}
		if i := strings.Index(req.Text, "Marie"); i >= 0 {
			ents = append(ents, entity{Type: "PERSON", Start: i, End: i + 5})
		}
		json.NewEncoder(w).Encode(map[string]any{"entities": ents})
	}))
	defer srv.Close()
	c := New(srv.URL, time.Second)

	if got, _ := c.Detect(context.Background(), "What is the capital of France?"); len(got) != 0 {
		t.Errorf("a place on its own: %+v, want nothing redacted", got)
	}
	got, _ := c.Detect(context.Background(), "Marie lives in France.")
	if len(got) != 2 {
		t.Errorf("a place next to a name: %+v, want both", got)
	}
}
