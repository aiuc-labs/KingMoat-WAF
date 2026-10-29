package aisession

// Request-side capture: normalize provider-specific conversation shapes into
// [{role, content}], replace non-text parts with placeholders, truncate to
// the configured cap and optionally sanitize. Pure functions, table-tested.

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// NormalizeRequest converts a buffered LLM request body into the normalized
// payload. body may be nil/empty (unbuffered) — the caller records metadata
// with TruncIn. maxBytes applies to every captured string.
func NormalizeRequest(provider, operation string, body []byte, maxBytes int) RequestPayload {
	if len(body) == 0 {
		return RequestPayload{}
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return RequestPayload{Raw: truncate(string(body), maxBytes)}
	}
	switch provider {
	case "openai", "minimax", "sensenova", "baidu":
		// all four speak the openai request shape (messages / prompt; baidu
		// also carries a top-level system which openaiRequest already reads
		// via the anthropic-style path below)
		return openaiRequest(raw, operation, maxBytes)
	case "anthropic":
		return anthropicRequest(raw, maxBytes)
	case "gemini":
		return geminiRequest(raw, maxBytes)
	case "dashscope":
		return dashscopeRequest(raw, maxBytes)
	default:
		return RequestPayload{Raw: truncate(string(body), maxBytes)}
	}
}

// dashscopeRequest flattens the native input.messages nesting into the
// canonical message array.
func dashscopeRequest(raw map[string]any, maxBytes int) RequestPayload {
	var p RequestPayload
	input, ok := raw["input"].(map[string]any)
	if !ok {
		if txt, ok := raw["prompt"].(string); ok {
			p.Messages = mustJSON([]Message{{Role: "user", Content: truncate(txt, maxBytes)}})
		}
		return p
	}
	if msgs, ok := input["messages"].([]any); ok {
		p.Messages = mustJSON(normalizeMessageArray(msgs, maxBytes))
	} else if txt, ok := input["prompt"].(string); ok {
		p.Messages = mustJSON([]Message{{Role: "user", Content: truncate(txt, maxBytes)}})
	}
	return p
}

func openaiRequest(raw map[string]any, operation string, maxBytes int) RequestPayload {
	var p RequestPayload
	if operation == "completion" {
		if prompt, ok := raw["prompt"].(string); ok {
			p.Messages = mustJSON([]Message{{Role: "user", Content: truncate(prompt, maxBytes)}})
		}
		return p
	}
	// chat / responses / embeddings: messages-style input
	if msgs, ok := raw["messages"].([]any); ok {
		p.Messages = mustJSON(normalizeMessageArray(msgs, maxBytes))
	} else if input, ok := raw["input"].(string); ok {
		p.Messages = mustJSON([]Message{{Role: "user", Content: truncate(input, maxBytes)}})
	} else if input, ok := raw["input"].([]any); ok {
		p.Messages = mustJSON(normalizeMessageArray(input, maxBytes))
	}
	// baidu qianfan carries the persona as a top-level system string (also
	// harmless for openai-shaped bodies, which never have one)
	if sys, ok := raw["system"].(string); ok {
		p.System = truncate(sys, maxBytes)
	}
	return p
}

func anthropicRequest(raw map[string]any, maxBytes int) RequestPayload {
	var p RequestPayload
	if sys, ok := raw["system"].(string); ok {
		p.System = truncate(sys, maxBytes)
	}
	if msgs, ok := raw["messages"].([]any); ok {
		p.Messages = mustJSON(normalizeMessageArray(msgs, maxBytes))
	}
	return p
}

func geminiRequest(raw map[string]any, maxBytes int) RequestPayload {
	var p RequestPayload
	contents, ok := raw["contents"].([]any)
	if !ok {
		return p
	}
	msgs := make([]Message, 0, min(len(contents), 128))
	budget := maxBytes
	for _, c := range contents {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		role, _ := cm["role"].(string)
		if role == "" {
			role = "user"
		}
		if len(msgs) >= 128 || budget <= 0 {
			msgs = append(msgs, Message{Role: role, Content: fmt.Sprintf("[TRUNCATED: more contents over capture budget]")})
			break
		}
		txt := partsText(cm["parts"], budget)
		budget -= len(txt)
		msgs = append(msgs, Message{Role: role, Content: txt})
	}
	p.Messages = mustJSON(msgs)
	// systemInstruction → system
	if si, ok := raw["systemInstruction"].(map[string]any); ok {
		p.System = truncate(partsText(si["parts"], maxBytes), maxBytes)
	}
	return p
}

// normalizeMessageArray converts openai/anthropic style message arrays,
// flattening string or multipart content into plain text with placeholders.
// A shared byte budget caps the whole conversation: once exhausted (or past
// maxMessages turns), remaining messages collapse into one placeholder so a
// long chat cannot inflate a single record past the uplink limits.
func normalizeMessageArray(msgs []any, maxBytes int) []Message {
	const maxMessages = 128
	out := make([]Message, 0, min(len(msgs), maxMessages))
	budget := maxBytes
	for i, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		role, _ := mm["role"].(string)
		if len(out) >= maxMessages || budget <= 0 {
			out = append(out, Message{Role: role, Content: fmt.Sprintf("[TRUNCATED: %d more messages over capture budget]", len(msgs)-i)})
			break
		}
		switch content := mm["content"].(type) {
		case string:
			c := truncate(content, budget)
			budget -= len(c)
			out = append(out, Message{Role: role, Content: c})
		case []any:
			c := partsText(content, budget)
			budget -= len(c)
			out = append(out, Message{Role: role, Content: c})
		case nil:
			out = append(out, Message{Role: role})
		default:
			b, _ := json.Marshal(content)
			c := truncate(string(b), budget)
			budget -= len(c)
			out = append(out, Message{Role: role, Content: c})
		}
	}
	return out
}

// partsText flattens a multipart parts array (openai content parts / gemini
// parts): text parts join, everything else becomes a size-tagged placeholder.
func partsText(parts any, maxBytes int) string {
	arr, ok := parts.([]any)
	if !ok {
		return ""
	}
	var b strings.Builder
	for _, part := range arr {
		pm, ok := part.(map[string]any)
		if !ok {
			continue
		}
		if txt, ok := pm["text"].(string); ok {
			b.WriteString(txt)
			continue
		}
		if iu, ok := pm["image_url"].(map[string]any); ok {
			if u, ok := iu["url"].(string); ok {
				b.WriteString(fmt.Sprintf("[IMG %s len=%d]", kindOf(u), len(u)))
			}
			continue
		}
		if id, ok := pm["inline_data"].(map[string]any); ok {
			mime, _ := id["mime_type"].(string)
			d, _ := id["data"].(string)
			b.WriteString(fmt.Sprintf("[%s base64 len=%d]", strings.ToUpper(mime), len(d)))
			continue
		}
		// unknown part type: keep its keys visible without values
		keys := make([]string, 0, len(pm))
		for k := range pm {
			keys = append(keys, k)
		}
		b.WriteString(fmt.Sprintf("[PART %s]", strings.Join(keys, ",")))
	}
	return truncate(b.String(), maxBytes)
}

func kindOf(u string) string {
	switch {
	case strings.HasPrefix(u, "data:image"):
		return "image"
	case strings.HasPrefix(u, "data:audio"):
		return "audio"
	case strings.HasPrefix(u, "data:video"):
		return "video"
	default:
		return "url"
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

func truncate(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	// cut at a rune boundary: drop trailing partial-rune bytes (at most 3)
	cut := s[:maxBytes]
	for i := 0; i < 3 && len(cut) > 0 && !utf8.ValidString(cut); i++ {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// Sanitize masks obvious secrets in captured prompt/output content
// (redact_content default on). Deliberately conservative: only high-signal
// token shapes, so conversational text stays readable for auditors.
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	for _, re := range sensitivePatterns {
		// $1/$3 preserve the JSON key and closing quote for the credential-
		// field pattern; for group-less patterns they expand to empty.
		s = re.ReplaceAllString(s, "$1[REDACTED]$3")
	}
	return s
}

func SanitizeRecord(r *Record) {
	r.Request.System = Sanitize(r.Request.System)
	if len(r.Request.Messages) > 0 {
		var msgs []Message
		if err := json.Unmarshal(r.Request.Messages, &msgs); err == nil {
			for i := range msgs {
				msgs[i].Content = Sanitize(msgs[i].Content)
			}
			r.Request.Messages = mustJSON(msgs)
		}
	}
	r.Request.Raw = Sanitize(r.Request.Raw)
	r.Response.Text = Sanitize(r.Response.Text)
	r.Response.Raw = Sanitize(r.Response.Raw)
	// The full request URL may carry provider credentials in the query
	// (Gemini ?key=AIza...); mask secret query values before anything is
	// persisted, shipped or displayed.
	r.URL = SanitizeURL(r.URL)
}

// SanitizeURL masks secret query-parameter values (URLs are NOT run through
// the general text patterns: path hex segments would be mangled).
func SanitizeURL(u string) string {
	if u == "" {
		return u
	}
	return querySecretRe.ReplaceAllString(u, "${1}[REDACTED]")
}
