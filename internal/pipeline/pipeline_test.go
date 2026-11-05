package pipeline

import (
	"context"
	"testing"
)

// fakeCheck returns a fixed decision and records that it ran.
type fakeCheck struct {
	name   string
	action Action
	ran    *bool
	modify func(*Request)
}

func (f fakeCheck) Name() string { return f.name }

func (f fakeCheck) Check(_ context.Context, req *Request) Decision {
	if f.ran != nil {
		*f.ran = true
	}
	if f.modify != nil {
		f.modify(req)
	}
	return Decision{Action: f.action, Reason: f.name + " says " + string(f.action)}
}

type panicCheck struct{}

func (panicCheck) Name() string                             { return "buggy" }
func (panicCheck) Check(context.Context, *Request) Decision { panic("oops") }

func newRequest() *Request {
	req, _ := ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	return req
}

func TestAllAllow(t *testing.T) {
	res := New(fakeCheck{name: "a", action: Allow}, fakeCheck{name: "b", action: Allow}).
		Run(context.Background(), newRequest())
	if res.Action != Allow || len(res.Trace) != 2 {
		t.Errorf("got %+v, want allow with 2 steps", res)
	}
}

func TestModifyContinuesAndLaterChecksSeeTheChange(t *testing.T) {
	var sawModel string
	rename := fakeCheck{name: "rename", action: Modify, modify: func(r *Request) { r.Model = "safe-model" }}
	observe := fakeCheck{name: "observe", action: Allow, modify: func(r *Request) { sawModel = r.Model }}

	res := New(rename, observe).Run(context.Background(), newRequest())
	if res.Action != Modify {
		t.Errorf("action = %s, want modify", res.Action)
	}
	if sawModel != "safe-model" {
		t.Errorf("later check saw model %q, want the modified one", sawModel)
	}
}

func TestBlockAndHoldStopThePipeline(t *testing.T) {
	for _, action := range []Action{Block, Hold} {
		t.Run(string(action), func(t *testing.T) {
			ran := false
			res := New(
				fakeCheck{name: "first", action: Modify},
				fakeCheck{name: "stopper", action: action},
				fakeCheck{name: "never", action: Allow, ran: &ran},
			).Run(context.Background(), newRequest())

			if res.Action != action || res.Check != "stopper" {
				t.Errorf("got action=%s check=%s, want %s by stopper", res.Action, res.Check, action)
			}
			if ran {
				t.Error("a check after the stopper still ran")
			}
		})
	}
}

func TestPanicBecomesBlock(t *testing.T) {
	res := New(panicCheck{}).Run(context.Background(), newRequest())
	if res.Action != Block || res.Check != "buggy" {
		t.Errorf("got %+v, want block by buggy", res)
	}
}

func TestUnknownActionBecomesBlock(t *testing.T) {
	res := New(fakeCheck{name: "weird", action: "maybe"}).Run(context.Background(), newRequest())
	if res.Action != Block {
		t.Errorf("action = %s, want block", res.Action)
	}
}

func TestNoChecksAllows(t *testing.T) {
	if res := New().Run(context.Background(), newRequest()); res.Action != Allow {
		t.Errorf("action = %s, want allow", res.Action)
	}
}
