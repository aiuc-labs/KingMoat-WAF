package aisession

// LLM API protocol identification: suffix-based path matching double-checked
// against request-body JSON features, so reverse-proxied deployments with
// arbitrary prefixes (e.g. /ai/v1/chat/completions) are discovered while
// ordinary business APIs stay below the false-positive floor.

import (
	"encoding/json"
	"strings"
)

// Match is the result of identifying one request against the protocol matrix.
type Match struct {
	Provider  string // openai | anthropic | gemini | baidu | dashscope | minimax | sensenova | unknown
	Operation string // chat | completion | responses | embeddings | messages | generate
	Model     string // extracted from the body (or the gemini URL path)
	Stream    bool   // stream predicted from body.stream / alt=sse
	Unknown   bool   // provider=unknown fallback (include_unknown)
}

// Suffix candidates are matched against the lowercased path with any prefix
// allowed; POST is required by the caller.
var suffixes = []struct {
	suffix     string
	provider   string
	operation  string
	embeddings bool
	contains   bool // match anywhere in the path instead of the suffix
}{
	{"/chat/completions", "openai", "chat", false, false},
	{"/completions", "openai", "completion", false, false},
	{"/responses", "openai", "responses", false, false},
	{"/embeddings", "openai", "embeddings", true, false},
	{"/messages", "anthropic", "messages", false, false},
	{":generatecontent", "gemini", "generate", false, false},
	{":streamgeneratecontent", "gemini", "generate", false, false},
	// MiniMax: /v1/text/chatcompletion_v2 (joined, not covered by /chat/completions)
	{"/chatcompletion_v2", "minimax", "chat", false, false},
	// SenseNova native: /v1/llm/chat-completions (hyphenated variant)
	{"/chat-completions", "sensenova", "chat", false, false},
	// Baidu Qianfan ERNIE: the tail is the model or a user-defined endpoint
	// name (completions_pro, ...), so only the workshop segment is stable.
	{"/wenxinworkshop/", "baidu", "chat", false, true},
	// Aliyun DashScope / Model Studio native: /api/v1/services/aigc/
	// {text,multimodal}-generation/generation
	{"/services/aigc/", "dashscope", "generate", false, true},
}

// Identify returns the protocol match for one request. body may be nil
// (unbuffered/oversized): in that case only the path suffix is available and
// the caller records metadata with trunc_in (identified=true, no features).
// includeEmbeddings / includeUnknown mirror the ai_audit toggles.
func Identify(method, path string, body []byte, includeEmbeddings, includeUnknown bool) (Match, bool) {
	if !strings.EqualFold(method, "POST") {
		return Match{}, false
	}
	// strip query before suffix matching, but remember alt=sse first
	// (gemini stream URLs carry it as ?alt=sse)
	lq := strings.ToLower(path)
	streamByQuery := strings.Contains(lq, "alt=sse")
	if q := strings.IndexAny(path, "?"); q >= 0 {
		path = path[:q]
	}
	lp := strings.ToLower(path)
	for _, s := range suffixes {
		if s.embeddings && !includeEmbeddings {
			continue
		}
		if s.contains {
			if !strings.Contains(lp, s.suffix) {
				continue
			}
		} else if !strings.HasSuffix(lp, s.suffix) {
			continue
		}
		m := Match{Provider: s.provider, Operation: s.operation}
		if s.provider == "baidu" {
			// .../chat/{model-endpoint} vs .../embeddings/...: the operation
			// rides on the segment after the workshop marker.
			if strings.Contains(lp, "/embeddings") {
				if !includeEmbeddings {
					continue
				}
				m.Operation = "embeddings"
			} else if i := strings.Index(lp, "/chat/"); i >= 0 {
				m.Model = strings.Trim(strings.SplitN(path[i+len("/chat/"):], "?", 2)[0], "/")
			}
		}
		if s.provider == "gemini" {
			m.Model = geminiModelFromPath(path)
			m.Stream = strings.Contains(lp, "streamgeneratecontent")
		}
		if len(body) == 0 {
			// path-only match: caller records metadata (no content captured)
			return m, true
		}
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			return Match{}, false // body present but not JSON: not an LLM call
		}
		switch s.provider {
		case "openai":
			model, _ := raw["model"].(string)
			m.Model = model
			if s.operation == "completion" {
				if _, ok := raw["prompt"]; !ok {
					return Match{}, false
				}
			} else if s.operation == "chat" {
				if _, ok := raw["messages"].([]any); !ok {
					return Match{}, false
				}
			} else if s.operation == "responses" {
				if _, ok := raw["input"]; !ok {
					return Match{}, false
				}
			} else if s.operation == "embeddings" {
				if _, ok := raw["input"]; !ok {
					return Match{}, false
				}
			}
			m.Stream = raw["stream"] == true
		case "anthropic":
			model, _ := raw["model"].(string)
			m.Model = model
			_, hasMsgs := raw["messages"]
			_, hasMax := raw["max_tokens"]
			if !hasMsgs || !hasMax {
				return Match{}, false
			}
			m.Stream = raw["stream"] == true
		case "gemini":
			contents, ok := raw["contents"].([]any)
			if !ok || len(contents) == 0 {
				return Match{}, false
			}
			// body may carry model too; path-derived model wins when present
			if m.Model == "" {
				m.Model, _ = raw["model"].(string)
			}
			m.Stream = streamByQuery
		case "baidu":
			// body shape equals openai (messages / input for embeddings); the
			// model lives in the path, not the body.
			if m.Operation == "embeddings" {
				if _, ok := raw["input"]; !ok {
					return Match{}, false
				}
			} else if _, ok := raw["messages"].([]any); !ok {
				return Match{}, false
			}
			m.Stream = raw["stream"] == true
		case "dashscope":
			// native shape: {"model", "input": {"messages"|"prompt"}, "parameters"}
			if _, ok := raw["input"]; !ok {
				return Match{}, false
			}
			if m.Model == "" {
				m.Model, _ = raw["model"].(string)
			}
			// streaming is signalled by the X-DashScope-SSE header which is not
			// visible here; HandleResponse flips stream on the Content-Type.
			m.Stream = streamByQuery
		case "minimax":
			model, _ := raw["model"].(string)
			m.Model = model
			if _, ok := raw["messages"].([]any); !ok {
				return Match{}, false
			}
			m.Stream = raw["stream"] == true
		case "sensenova":
			model, _ := raw["model"].(string)
			m.Model = model
			if _, ok := raw["messages"].([]any); !ok {
				return Match{}, false
			}
			m.Stream = raw["stream"] == true
		}
		return m, true
	}
	// unknown fallback: /v1/ path + body model field, features not fully matched
	if includeUnknown && len(body) > 0 && strings.Contains(lp, "/v1/") {
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err == nil {
			if _, ok := raw["model"].(string); ok {
				model, _ := raw["model"].(string)
				return Match{Provider: "unknown", Model: model, Unknown: true,
					Operation: "unknown", Stream: raw["stream"] == true}, true
			}
		}
	}
	return Match{}, false
}

// geminiModelFromPath extracts models/{model}:action from the URL path.
func geminiModelFromPath(path string) string {
	i := strings.LastIndex(strings.ToLower(path), "models/")
	if i < 0 {
		return ""
	}
	rest := path[i+len("models/"):]
	if j := strings.Index(rest, ":"); j >= 0 {
		rest = rest[:j]
	}
	if k := strings.IndexAny(rest, "?#"); k >= 0 {
		rest = rest[:k]
	}
	return strings.Trim(rest, "/")
}
