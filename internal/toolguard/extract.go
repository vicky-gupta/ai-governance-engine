package toolguard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sort"
)

// Call is one tool call the model wants the agent to make.
type Call struct {
	Name      string
	Arguments string // raw JSON text, exactly as the model wrote it
}

// fromJSON reads the tool calls in a normal (non-streamed) response.
func fromJSON(body []byte) []Call {
	var resp struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
				FunctionCall *struct { // the older single-function format
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function_call"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil
	}
	var calls []Call
	for _, c := range resp.Choices {
		for _, tc := range c.Message.ToolCalls {
			calls = append(calls, Call{Name: tc.Function.Name, Arguments: tc.Function.Arguments})
		}
		if fc := c.Message.FunctionCall; fc != nil {
			calls = append(calls, Call{Name: fc.Name, Arguments: fc.Arguments})
		}
	}
	return calls
}

// fromStream reads the tool calls in a streamed response. A tool call
// arrives in pieces: the first piece has its name, and the arguments
// come as text fragments spread over many chunks, keyed by the choice
// and the call's index. They are put back together here.
func fromStream(body []byte) []Call {
	type key struct{ choice, call int }
	parts := map[key]*Call{}

	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), len(body)+1)
	for sc.Scan() {
		data, ok := bytes.CutPrefix(bytes.TrimSpace(sc.Bytes()), []byte("data:"))
		if !ok {
			continue
		}
		var chunk struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(bytes.TrimSpace(data), &chunk) != nil {
			continue // e.g. "[DONE]"
		}
		for _, c := range chunk.Choices {
			for _, tc := range c.Delta.ToolCalls {
				k := key{c.Index, tc.Index}
				if parts[k] == nil {
					parts[k] = &Call{}
				}
				parts[k].Name += tc.Function.Name
				parts[k].Arguments += tc.Function.Arguments
			}
		}
	}

	keys := make([]key, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].choice != keys[j].choice {
			return keys[i].choice < keys[j].choice
		}
		return keys[i].call < keys[j].call
	})
	calls := make([]Call, 0, len(keys))
	for _, k := range keys {
		calls = append(calls, *parts[k])
	}
	return calls
}
