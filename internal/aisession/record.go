package aisession

// Record is the canonical AI session-audit entry: identical shape for the
// node ring, the central ai_sessions table, the console page and outbound
// shipping. Core transaction fields (ts/trace_id/site/client_ip/method/path/
// url/status/user_agent) intentionally mirror logstore.Event and
// accesslog.Entry so the three log families cross-reference by trace_id.

import "encoding/json"

type Record struct {
	ID          string          `json:"id"`
	TS          string          `json:"ts"`
	TraceID     string          `json:"trace_id,omitempty"`
	Site        string          `json:"site,omitempty"`
	ClientIP    string          `json:"client_ip,omitempty"`
	NodeID      string          `json:"node_id,omitempty"`
	Method      string          `json:"method,omitempty"`
	Path        string          `json:"path,omitempty"`
	URL         string          `json:"url,omitempty"`
	Status      int             `json:"status,omitempty"`
	UserAgent   string          `json:"user_agent,omitempty"`
	DurationMS  int64           `json:"duration_ms,omitempty"`
	Provider    string          `json:"provider"` // openai | anthropic | gemini | unknown
	Operation   string          `json:"operation,omitempty"`
	Model       string          `json:"model,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
	Request     RequestPayload  `json:"request,omitempty"`
	Response    ResponsePayload `json:"response,omitempty"`
	Usage       *Usage          `json:"usage,omitempty"`
	ReqBytes    int64           `json:"req_bytes,omitempty"`
	RespBytes   int64           `json:"resp_bytes,omitempty"`
	TruncIn     bool            `json:"trunc_in,omitempty"`
	TruncOut    bool            `json:"trunc_out,omitempty"`
	Interrupted bool            `json:"interrupted,omitempty"`
	Err         string          `json:"err,omitempty"`
}

// RequestPayload carries the normalized conversation. Messages is a JSON
// array of {role, content}; non-text parts become placeholders. Raw keeps a
// truncated copy of the original body when normalization fails.
type RequestPayload struct {
	System   string          `json:"system,omitempty"`
	Messages json.RawMessage `json:"messages,omitempty"`
	Raw      string          `json:"raw,omitempty"`
}

type ResponsePayload struct {
	Text string `json:"text,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}

// Message is one normalized conversation turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
