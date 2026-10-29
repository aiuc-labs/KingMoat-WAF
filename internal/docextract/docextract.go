// Package docextract turns operator-supplied documents (PDF, Word, Excel, CSV,
// HTML, text) and remote advisory pages into plain text for the rule-expert
// prompt. Everything is done in memory: nothing is written to disk and the raw
// markup is never returned.
package docextract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kingmoat/kingmoat/internal/safefetch"
)

// Limits shared by every input source.
const (
	// MaxInputBytes bounds one uploaded document (the API layer enforces the
	// same number with MaxBytesReader).
	MaxInputBytes = 8 << 20 // 8 MiB
	// MaxTextBytes bounds the extracted body handed to the prompt.
	MaxTextBytes = 256 << 10 // 256 KiB
	// maxRows bounds table-like inputs (CSV, XLSX, UI tables).
	maxRows = 500
	// maxCSVBytes bounds one CSV document.
	maxCSVBytes = 1 << 20
	// maxPDFPages bounds PDF traversal (a malformed page tree must not spin).
	maxPDFPages = 200
	// maxArchiveEntries bounds zip entries inspected in an OOXML container.
	maxArchiveEntries = 2048
	// maxURLBody bounds a fetched advisory page.
	maxURLBody = 2 << 20
)

// SourceType values reported in Result.
const (
	SourceText  = "text"
	SourceFile  = "file"
	SourceURL   = "url"
	SourceTable = "table"
)

// Sentinel errors. The API layer maps each to its machine-readable code and
// returns the message as-is (they are already user-facing Chinese).
var (
	ErrTooLarge    = errors.New("文件超过 8MB 上限，请精简后再试")
	ErrUnsupported = errors.New("暂不支持该文件类型，请上传 PDF / Word(.docx) / Excel(.xlsx) / CSV / HTML / 文本文件，或直接粘贴正文")
	ErrDocLegacy   = errors.New("暂不支持旧版 .doc 格式，请另存为 .docx 后重试")
	ErrXLSXLegacy  = errors.New("暂不支持旧版 .xls 格式，请另存为 .xlsx 后重试")
	ErrPDFEncrypted = errors.New("无法解析该 PDF（可能为加密文档），请粘贴正文")
	ErrPDFNoText    = errors.New("未检测到可解析文本（可能为扫描件），请粘贴正文")
	ErrPDFBroken    = errors.New("无法解析该 PDF（可能为加密文档），请粘贴正文")
	// ErrJSShell: the page is a client-rendered SPA shell — the body never
	// reaches the initial HTML, so no server-side parser can extract it.
	ErrJSShell = errors.New("该页面由前端脚本渲染（SPA），服务端只能取到标题壳、取不到正文。请改用「上传文件」或「粘贴文本」，或直接上传页面截图（多模态模型识别）")
)

// Result is one extraction outcome.
type Result struct {
	Text       string   `json:"text"`
	SourceType string   `json:"source_type"`
	SourceName string   `json:"source_name"`
	Chars      int      `json:"chars"`
	Truncated  bool     `json:"truncated"`
	Warnings   []string `json:"warnings"`
}

func (r *Result) warn(msg string) {
	for _, w := range r.Warnings {
		if w == msg {
			return
		}
	}
	r.Warnings = append(r.Warnings, msg)
}

// finalize applies the shared text budget and fills the derived fields.
func (r *Result) finalize() Result {
	r.Text = strings.TrimSpace(r.Text)
	if len(r.Text) > MaxTextBytes {
		r.Text = truncateUTF8(r.Text, MaxTextBytes)
		r.Truncated = true
		r.warn("内容过长已截断")
	}
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	r.Chars = utf8.RuneCountInString(r.Text)
	return *r
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ExtractFile dispatches on the file extension.
func ExtractFile(name string, data []byte) (Result, error) {
	if len(data) > MaxInputBytes {
		return Result{}, ErrTooLarge
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(name)))
	res := Result{SourceType: SourceFile, SourceName: name}

	switch ext {
	case ".pdf":
		text, err := extractPDF(data)
		if err != nil {
			return Result{}, err
		}
		res.Text = text
	case ".docx":
		text, err := extractDOCX(data)
		if err != nil {
			return Result{}, err
		}
		res.Text = text
	case ".doc":
		return Result{}, ErrDocLegacy
	case ".xlsx":
		text, err := extractXLSX(data)
		if err != nil {
			return Result{}, err
		}
		res.Text = text
	case ".xls":
		return Result{}, ErrXLSXLegacy
	case ".csv":
		text, truncated, err := extractCSV(data)
		if err != nil {
			return Result{}, err
		}
		res.Text = text
		if truncated {
			res.Truncated = true
			res.warn("CSV 行数超过 500 行，已截断")
		}
	case ".html", ".htm":
		res.Text = HTMLToText(string(data))
	case ".txt", ".md", ".markdown", ".log", "":
		if !utf8.Valid(data) {
			return Result{}, ErrUnsupported
		}
		res.Text = string(data)
	case ".json":
		text, err := extractJSON(data)
		if err != nil {
			// Unparseable JSON is still readable text in most advisories.
			if !utf8.Valid(data) {
				return Result{}, ErrUnsupported
			}
			res.Text = string(data)
		} else {
			res.Text = text
		}
	default:
		if isTextLike(data) {
			res.Text = string(data)
			break
		}
		return Result{}, ErrUnsupported
	}

	out := res.finalize()
	if out.Text == "" {
		return Result{}, fmt.Errorf("未从文件中提取到文本内容，请检查文件后重试")
	}
	return out, nil
}

// isTextLike reports whether the bytes look like UTF-8 text with no NUL bytes
// (a cheap binary heuristic for unlabelled uploads).
func isTextLike(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return true
}

// ExtractURL fetches a remote advisory page and returns its text. The fetch
// reuses the safefetch policy, so requires_external also governs which
// addresses a link may reach.
func ExtractURL(ctx context.Context, rawURL string, allowPrivate bool) (Result, error) {
	body, status, contentType, err := safefetch.Get(ctx, rawURL, safefetch.Options{
		AllowPrivate: allowPrivate,
		Timeout:      15 * time.Second,
		MaxBytes:     maxURLBody,
		AcceptTypes:  []string{"text/html", "application/xhtml+xml", "text/plain", "text/xml", "application/xml"},
	})
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 400 {
		return Result{}, fmt.Errorf("目标页面返回状态码 %d", status)
	}
	u, _ := url.Parse(rawURL)
	name := ""
	if u != nil {
		name = u.Hostname()
	}
	res := Result{SourceType: SourceURL, SourceName: name}
	if strings.Contains(strings.ToLower(contentType), "html") {
		raw := string(body)
		res.Text = HTMLToText(raw)
		// SPA pages often ship their data as an embedded JSON state blob that
		// HTMLToText strips along with the other scripts. Recover it before
		// declaring the page unparseable — this is what makes Next.js / Nuxt /
		// ld+json pages work without a headless browser.
		if state := extractEmbeddedState(raw); state != "" {
			if res.Text != "" {
				res.Text = res.Text + "\n\n" + state
			} else {
				res.Text = state
			}
		}
		if looksLikeJSShell(res.Text, raw) {
			return Result{}, ErrJSShell
		}
	} else {
		if !utf8.Valid(body) {
			return Result{}, fmt.Errorf("目标页面内容不是可识别的文本")
		}
		res.Text = string(body)
	}
	out := res.finalize()
	if out.Text == "" {
		return Result{}, fmt.Errorf("目标页面未提取到正文内容")
	}
	return out, nil
}

// ExtractTable renders the console's table editor rows (JSON array of rows,
// either {"字段": "值"} objects or string arrays) as " | " separated lines.
func ExtractTable(rowsJSON []byte) (Result, error) {
	trimmed := strings.TrimSpace(string(rowsJSON))
	if trimmed == "" {
		return Result{}, fmt.Errorf("表格内容为空")
	}
	if len(rowsJSON) > MaxInputBytes {
		return Result{}, ErrTooLarge
	}
	res := Result{SourceType: SourceTable, SourceName: "table"}

	if rows, ok := parseTableRows(rowsJSON); ok {
		var b strings.Builder
		for i, row := range rows {
			if i >= maxRows {
				res.warn("表格行数超过 500 行，已截断")
				break
			}
			cells := make([]string, 0, len(row))
			for _, c := range row {
				if c = strings.TrimSpace(c); c != "" {
					cells = append(cells, c)
				}
			}
			if len(cells) == 0 {
				continue
			}
			b.WriteString(strings.Join(cells, " | "))
			b.WriteString("\n")
		}
		res.Text = b.String()
	} else {
		return Result{}, fmt.Errorf("表格数据格式不正确，应为行数组")
	}
	out := res.finalize()
	if out.Text == "" {
		return Result{}, fmt.Errorf("表格内容为空")
	}
	return out, nil
}

// parseTableRows accepts both row shapes the UI produces.
func parseTableRows(rowsJSON []byte) ([][]string, bool) {
	var arrayRows [][]string
	if err := json.Unmarshal(rowsJSON, &arrayRows); err == nil {
		return arrayRows, true
	}
	var objRows []map[string]string
	if err := json.Unmarshal(rowsJSON, &objRows); err == nil {
		out := make([][]string, 0, len(objRows))
		for _, row := range objRows {
			keys := make([]string, 0, len(row))
			for k := range row {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			cells := make([]string, 0, len(keys)*2)
			for _, k := range keys {
				v := strings.TrimSpace(row[k])
				if v == "" {
					continue
				}
				cells = append(cells, k+": "+v)
			}
			out = append(out, cells)
		}
		return out, true
	}
	return nil, false
}

// extractJSON flattens a JSON document into "key: value" lines.
func extractJSON(data []byte) (string, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return "", err
	}
	var b strings.Builder
	flattenJSON(&b, "", v, 0)
	return b.String(), nil
}

func flattenJSON(b *strings.Builder, prefix string, v any, depth int) {
	if depth > 12 {
		return
	}
	indent := strings.Repeat("  ", depth)
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenJSON(b, prefix+k, t[k], depth+1)
		}
	case []any:
		for i, item := range t {
			flattenJSON(b, fmt.Sprintf("%s[%d]", prefix, i), item, depth+1)
		}
	default:
		key := prefix
		if key == "" {
			key = "value"
		}
		fmt.Fprintf(b, "%s%s: %v\n", indent, key, t)
	}
}

var (
	reScriptStyle = regexp.MustCompile(`(?is)<(script|style|noscript)\b[^>]*>.*?</(script|style|noscript)\s*>`)
	reBr          = regexp.MustCompile(`(?i)<br\s*/?>`)
	reBlockClose  = regexp.MustCompile(`(?i)</(p|div|li|tr|h[1-6]|section|article|header|footer|table|ul|ol|blockquote|pre|dd|dt)\s*>`)
	reBlockOpen   = regexp.MustCompile(`(?i)<(p|div|li|tr|h[1-6]|section|article|header|footer|table|ul|ol|blockquote|pre|dd|dt)\b[^>]*>`)
	reAnyTag      = regexp.MustCompile(`(?s)<[^>]*>`)
	reHSpaces     = regexp.MustCompile(`[ \t\x{00a0}]+`)
	reBlankLines  = regexp.MustCompile(`\n\s*\n+`)
)


// reStateScript matches the script tags that carry page data as JSON: ld+json
// blocks plus the Next.js / Nuxt state scripts.
var reStateScript = regexp.MustCompile(`(?is)<script[^>]*(?:type=["\']application/(?:ld\+)?json["\']|id=["\'](?:__NEXT_DATA__|__NUXT_DATA__)["\'])[^>]*>(.*?)</script>`)

// reStateAssign matches inline "window.__SOMETHING__ =" state assignments.
var reStateAssign = regexp.MustCompile(`(?is)window\.__[A-Za-z0-9_]+__\s*=\s*`)

// reJSShellMarkers are the boilerplate lines client-rendered SPAs answer with
// when JavaScript is off — the signature of a body that never reaches the HTML.
var reJSShellMarkers = regexp.MustCompile(`(?i)(without javascript enabled|enable javascript|javascript is (?:disabled|required)|requires javascript)`)

// extractEmbeddedState recovers page data that ships as JSON inside the HTML.
// Only long leaf strings survive (UI chrome yields short labels and class
// names), rendered as "key: value" lines.
func extractEmbeddedState(raw string) string {
	var sb strings.Builder
	for _, m := range reStateScript.FindAllStringSubmatch(raw, -1) {
		collectJSONStrings(&sb, m[1], "")
	}
	for _, loc := range reStateAssign.FindAllStringIndex(raw, -1) {
		if body := jsonObjectAt(raw, loc[1]); body != "" {
			collectJSONStrings(&sb, body, "")
		}
	}
	return strings.TrimSpace(sb.String())
}

// jsonObjectAt returns the balanced JSON object starting at the first '{' after
// pos (string literals and escapes respected), or "".
func jsonObjectAt(s string, pos int) string {
	start := strings.IndexByte(s[pos:], '{')
	if start < 0 {
		return ""
	}
	start += pos
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// collectJSONStrings walks a JSON document and appends leaf strings long enough
// to be content (>= 24 runes) as "key: value" lines.
func collectJSONStrings(sb *strings.Builder, doc, key string) {
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		return
	}
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				walk(val, k)
			}
		case []any:
			for _, val := range t {
				walk(val, key)
			}
		case string:
			str := strings.TrimSpace(t)
			if utf8.RuneCountInString(str) < 24 {
				return
			}
			if key != "" {
				sb.WriteString(key)
				sb.WriteString(": ")
			}
			sb.WriteString(str)
			sb.WriteString("\n")
		}
	}
	walk(v, key)
}

// looksLikeJSShell reports whether the extracted text is just an SPA shell:
// a JavaScript-required notice, or almost no text next to a script-heavy body.
func looksLikeJSShell(text, html string) bool {
	if reJSShellMarkers.MatchString(html) {
		return true
	}
	return utf8.RuneCountInString(text) < 100 && strings.Count(html, "<script") >= 3
}

// HTMLToText converts markup into readable plain text: script/style blocks
// vanish, block-level tags become paragraph breaks, entities are decoded and
// whitespace is collapsed. Shared by the file, URL and text paths.
func HTMLToText(raw string) string {
	s := reScriptStyle.ReplaceAllString(raw, " ")
	s = reBr.ReplaceAllString(s, "\n")
	s = reBlockOpen.ReplaceAllString(s, "\n")
	s = reBlockClose.ReplaceAllString(s, "\n")
	s = reAnyTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = reHSpaces.ReplaceAllString(s, " ")

	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// inlineText collapses markup into one line (titles, summaries, JSON values).
func inlineText(raw string) string {
	s := reScriptStyle.ReplaceAllString(raw, " ")
	s = reAnyTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.TrimSpace(reHSpaces.ReplaceAllString(s, " "))
}