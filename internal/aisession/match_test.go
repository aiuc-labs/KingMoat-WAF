package aisession

import "testing"

func post(p string) (string, string) { return "POST", p }

func TestIdentifyOpenAIChatAnyPrefix(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	m, ok := Identify("POST", "/ai/v1/chat/completions", body, false, false)
	if !ok || m.Provider != "openai" || m.Operation != "chat" || m.Model != "gpt-4o" || !m.Stream {
		t.Fatalf("openai chat identify failed: %+v ok=%v", m, ok)
	}
}

func TestIdentifyOpenAICompletions(t *testing.T) {
	m, ok := Identify("POST", "/v1/completions", []byte(`{"model":"gpt-3.5-turbo-instruct","prompt":"hi"}`), false, false)
	if !ok || m.Provider != "openai" || m.Operation != "completion" || m.Model != "gpt-3.5-turbo-instruct" {
		t.Fatalf("openai completion identify failed: %+v ok=%v", m, ok)
	}
}

func TestIdentifyOpenAIResponses(t *testing.T) {
	m, ok := Identify("POST", "/openai/v1/responses", []byte(`{"model":"o4-mini","input":"hi"}`), false, false)
	if !ok || m.Provider != "openai" || m.Operation != "responses" || m.Model != "o4-mini" {
		t.Fatalf("openai responses identify failed: %+v ok=%v", m, ok)
	}
}

func TestIdentifyEmbeddingsGated(t *testing.T) {
	body := []byte(`{"model":"text-embedding-3","input":"hi"}`)
	if _, ok := Identify("POST", "/v1/embeddings", body, false, false); ok {
		t.Fatal("embeddings must be gated by include_embeddings")
	}
	if _, ok := Identify("POST", "/v1/embeddings", body, true, false); !ok {
		t.Fatal("embeddings with include_embeddings must match")
	}
}

func TestIdentifyAnthropic(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}],"max_tokens":1024,"stream":true}`)
	m, ok := Identify("POST", "/anthropic/v1/messages", body, false, false)
	if !ok || m.Provider != "anthropic" || m.Operation != "messages" || m.Model != "claude-sonnet-4" || !m.Stream {
		t.Fatalf("anthropic identify failed: %+v ok=%v", m, ok)
	}
	// missing max_tokens → reject
	if _, ok := Identify("POST", "/v1/messages", []byte(`{"model":"claude","messages":[]}`), false, false); ok {
		t.Fatal("anthropic without max_tokens must be rejected")
	}
}

func TestIdentifyGeminiSSEAndPath(t *testing.T) {
	body := []byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`)
	m, ok := Identify("POST", "/gemini/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse", body, false, false)
	if !ok || m.Provider != "gemini" || m.Model != "gemini-2.0-flash" || !m.Stream {
		t.Fatalf("gemini sse identify failed: %+v ok=%v", m, ok)
	}
	m, ok = Identify("POST", "/v1beta/models/gemini-1.5-pro:generateContent", body, false, false)
	if !ok || m.Provider != "gemini" || m.Model != "gemini-1.5-pro" || m.Stream {
		t.Fatalf("gemini non-sse identify failed: %+v ok=%v", m, ok)
	}
}

func TestIdentifyBodyNilPathOnly(t *testing.T) {
	m, ok := Identify("POST", "/v1/chat/completions", nil, false, false)
	if !ok || m.Provider != "openai" || m.Model != "" {
		t.Fatalf("nil body must yield path-only match: %+v ok=%v", m, ok)
	}
}

func TestIdentifyRejectsNonJSONAndWrongShape(t *testing.T) {
	if _, ok := Identify("POST", "/v1/chat/completions", []byte(`not-json`), false, false); ok {
		t.Fatal("non-JSON body must be rejected")
	}
	if _, ok := Identify("POST", "/v1/chat/completions", []byte(`{"model":"m"}`), false, false); ok {
		t.Fatal("chat without messages must be rejected")
	}
	if _, ok := Identify("GET", "/v1/chat/completions", nil, false, false); ok {
		t.Fatal("GET must be rejected")
	}
}

func TestIdentifyUnknownFallback(t *testing.T) {
	body := []byte(`{"model":"some-model","other":"field"}`)
	if _, ok := Identify("POST", "/v1/custom/thing", body, false, false); ok {
		t.Fatal("unknown fallback must be gated by include_unknown")
	}
	m, ok := Identify("POST", "/v1/custom/thing", body, false, true)
	if !ok || m.Provider != "unknown" || !m.Unknown || m.Model != "some-model" {
		t.Fatalf("unknown fallback failed: %+v ok=%v", m, ok)
	}
}

func TestGeminiModelFromPathEdge(t *testing.T) {
	if got := geminiModelFromPath("/v1beta/models/m1:generateContent"); got != "m1" {
		t.Fatalf("got %q", got)
	}
	if got := geminiModelFromPath("/plain/path"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}


// ---- domestic-unique providers ----

func TestIdentifyBaiduQianfan(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"}],"system":"be brief"}`)
	m, ok := Identify("POST", "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions_pro?access_token=24.abc", body, false, false)
	if !ok || m.Provider != "baidu" || m.Operation != "chat" || m.Model != "completions_pro" {
		t.Fatalf("baidu chat = %+v ok=%v", m, ok)
	}
	if m.Stream {
		t.Fatal("stream must follow body")
	}
	// custom endpoint name + stream flag
	m2, ok2 := Identify("POST", "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/my-app", []byte(`{"messages":[],"stream":true}`), false, false)
	if !ok2 || m2.Model != "my-app" || !m2.Stream {
		t.Fatalf("baidu custom = %+v ok=%v", m2, ok2)
	}
	// body without messages: double-check rejects
	if _, ok3 := Identify("POST", "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions_pro", []byte(`{"foo":1}`), false, false); ok3 {
		t.Fatal("baidu without messages must not match")
	}
}

func TestIdentifyBaiduEmbeddingsGated(t *testing.T) {
	body := []byte(`{"input":["text"]}`)
	if _, ok := Identify("POST", "/rpc/2.0/ai_custom/v1/wenxinworkshop/embeddings/embedding-v1", body, false, false); ok {
		t.Fatal("embeddings must be gated by include_embeddings")
	}
	m, ok := Identify("POST", "/rpc/2.0/ai_custom/v1/wenxinworkshop/embeddings/embedding-v1", body, true, false)
	if !ok || m.Provider != "baidu" || m.Operation != "embeddings" {
		t.Fatalf("baidu embeddings = %+v ok=%v", m, ok)
	}
}

func TestIdentifyDashScope(t *testing.T) {
	body := []byte(`{"model":"qwen-plus","input":{"messages":[{"role":"user","content":"hi"}]},"parameters":{"result_format":"message"}}`)
	m, ok := Identify("POST", "/api/v1/services/aigc/text-generation/generation", body, false, false)
	if !ok || m.Provider != "dashscope" || m.Operation != "generate" || m.Model != "qwen-plus" {
		t.Fatalf("dashscope = %+v ok=%v", m, ok)
	}
	// multimodal path matches the same contains rule
	if m2, ok2 := Identify("POST", "/api/v1/services/aigc/multimodal-generation/generation", body, false, false); !ok2 || m2.Provider != "dashscope" {
		t.Fatalf("dashscope multimodal = %+v ok=%v", m2, ok2)
	}
	// plain business path with /services/aigc/ absent must not match
	if _, ok3 := Identify("POST", "/api/v1/other/generation", body, false, false); ok3 {
		t.Fatal("non-aigc path must not match dashscope")
	}
}

func TestIdentifyMiniMax(t *testing.T) {
	body := []byte(`{"model":"MiniMax-M3","messages":[{"role":"user","content":"hi"}]}`)
	m, ok := Identify("POST", "/v1/text/chatcompletion_v2", body, false, false)
	if !ok || m.Provider != "minimax" || m.Model != "MiniMax-M3" {
		t.Fatalf("minimax = %+v ok=%v", m, ok)
	}
}

func TestIdentifySenseNovaNative(t *testing.T) {
	body := []byte(`{"model":"SenseChat-5","max_new_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`)
	m, ok := Identify("POST", "/v1/llm/chat-completions", body, false, false)
	if !ok || m.Provider != "sensenova" || m.Model != "SenseChat-5" {
		t.Fatalf("sensenova = %+v ok=%v", m, ok)
	}
}
