package docextract

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// buildPDF assembles a minimal one-page PDF with a correct xref table so the
// third-party parser accepts it. The text is drawn with the Helvetica base
// font; withText=false produces a page with an empty content stream (the
// "scanned document" shape).
func buildPDF(text string, withText bool) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, 6)
	writeObj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	writeObj(1, "<</Type/Catalog/Pages 2 0 R>>")
	writeObj(2, "<</Type/Pages/Kids[3 0 R]/Count 1>>")
	writeObj(3, "<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 300]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>")
	stream := ""
	if withText {
		stream = "BT /F1 12 Tf 20 250 Td (" + text + ") Tj ET"
	}
	writeObj(4, fmt.Sprintf("<</Length %d>>\nstream\n%s\nendstream", len(stream), stream))
	writeObj(5, "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>")
	xref := buf.Len()
	buf.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<</Size 6/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", xref)
	return buf.Bytes()
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractPDFText(t *testing.T) {
	data := buildPDF("CVE-2026-1234 remote code execution", true)
	res, err := ExtractFile("advisory.pdf", data)
	if err != nil {
		t.Fatalf("extract pdf: %v", err)
	}
	if !strings.Contains(res.Text, "CVE-2026-1234") {
		t.Fatalf("text = %q", res.Text)
	}
	if res.SourceType != SourceFile || res.SourceName != "advisory.pdf" || res.Chars == 0 {
		t.Fatalf("result metadata = %+v", res)
	}
}

func TestExtractPDFNoTextLayer(t *testing.T) {
	data := buildPDF("", false)
	_, err := ExtractFile("scan.pdf", data)
	if !errors.Is(err, ErrPDFNoText) {
		t.Fatalf("err = %v, want ErrPDFNoText", err)
	}

	// A non-PDF payload labelled .pdf is a parse failure, not a silent empty.
	if _, err := ExtractFile("broken.pdf", []byte("not a pdf at all")); !errors.Is(err, ErrPDFBroken) {
		t.Fatalf("broken pdf err = %v, want ErrPDFBroken", err)
	}
}

func TestExtractDOCXParagraphsAndTables(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>第一段：漏洞概述</w:t></w:r></w:p>
    <w:p><w:r><w:t>第二段：影响</w:t></w:r></w:p>
    <w:tbl>
      <w:tr><w:tc><w:p><w:r><w:t>编号</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>描述</w:t></w:r></w:p></w:tc></w:tr>
      <w:tr><w:tc><w:p><w:r><w:t>CVE-2026-1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>RCE</w:t></w:r></w:p></w:tc></w:tr>
    </w:tbl>
  </w:body>
</w:document>`
	data := buildZip(t, map[string]string{"word/document.xml": doc})
	res, err := ExtractFile("advisory.docx", data)
	if err != nil {
		t.Fatalf("extract docx: %v", err)
	}
	for _, want := range []string{"第一段：漏洞概述", "第二段：影响", "编号 | 描述", "CVE-2026-1 | RCE"} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("missing %q in %q", want, res.Text)
		}
	}
}

func TestExtractDOCRejected(t *testing.T) {
	_, err := ExtractFile("legacy.doc", []byte("OLE2"))
	if !errors.Is(err, ErrDocLegacy) {
		t.Fatalf("err = %v, want ErrDocLegacy", err)
	}
	if _, err := ExtractFile("legacy.xls", []byte("OLE2")); !errors.Is(err, ErrXLSXLegacy) {
		t.Fatalf("xls err = %v, want ErrXLSXLegacy", err)
	}
}

func TestExtractXLSXFirstSheet(t *testing.T) {
	shared := `<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <si><t>漏洞编号</t></si>
  <si><t>风险等级</t></si>
  <si><t>CVE-2026-9</t></si>
</sst>`
	sheet1 := `<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>
    <row r="2"><c r="A2" t="s"><v>2</v></c><c r="B2" t="inlineStr"><is><t>高危</t></is></c></row>
  </sheetData>
</worksheet>`
	sheet2 := `<worksheet><sheetData><row><c t="inlineStr"><is><t>SHOULD-NOT-APPEAR</t></is></c></row></sheetData></worksheet>`
	data := buildZip(t, map[string]string{
		"xl/sharedStrings.xml":      shared,
		"xl/worksheets/sheet1.xml":  sheet1,
		"xl/worksheets/sheet2.xml":  sheet2,
	})
	res, err := ExtractFile("advisory.xlsx", data)
	if err != nil {
		t.Fatalf("extract xlsx: %v", err)
	}
	if !strings.Contains(res.Text, "漏洞编号 | 风险等级") || !strings.Contains(res.Text, "CVE-2026-9 | 高危") {
		t.Fatalf("text = %q", res.Text)
	}
	if strings.Contains(res.Text, "SHOULD-NOT-APPEAR") {
		t.Fatalf("second sheet leaked into output: %q", res.Text)
	}
}

func TestExtractCSVLimit500Rows(t *testing.T) {
	var b strings.Builder
	b.WriteString("编号,描述,等级\n")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&b, "CVE-%d,说明%d,高\n", i, i)
	}
	res, err := ExtractFile("advisory.csv", []byte(b.String()))
	if err != nil {
		t.Fatalf("extract csv: %v", err)
	}
	if !res.Truncated {
		t.Fatal("600-row csv must be flagged truncated")
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "500") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v", res.Warnings)
	}
	lines := strings.Split(res.Text, "\n")
	if len(lines) != maxRows {
		t.Fatalf("lines = %d, want %d", len(lines), maxRows)
	}
}

func TestExtractHTMLBlocksToNewlines(t *testing.T) {
	htmlDoc := `<html><head><title>t</title><style>p{color:red}</style></head><body>
	<h1>安全通告</h1>
	<p>第一段</p><p>第二段<br>换行</p>
	<script>alert('x')</script>
	<div>第三段 &amp; 实体</div>
	</body></html>`
	res, err := ExtractFile("advisory.html", []byte(htmlDoc))
	if err != nil {
		t.Fatalf("extract html: %v", err)
	}
	if strings.Contains(res.Text, "alert") || strings.Contains(res.Text, "color:red") {
		t.Fatalf("script/style leaked: %q", res.Text)
	}
	for _, want := range []string{"安全通告", "第一段", "第二段", "换行", "第三段 & 实体"} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("missing %q in %q", want, res.Text)
		}
	}
	if strings.Count(res.Text, "\n") < 3 {
		t.Fatalf("block tags did not become newlines: %q", res.Text)
	}
}

func TestExtractURLRejectsPrivate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><p>内网通告正文</p></body></html>"))
	}))
	defer srv.Close()

	if _, err := ExtractURL(ctx, srv.URL, false); err == nil {
		t.Fatal("loopback URL must be rejected without allowPrivate")
	}

	res, err := ExtractURL(ctx, srv.URL, true)
	if err != nil {
		t.Fatalf("allowPrivate fetch failed: %v", err)
	}
	if res.SourceType != SourceURL || res.SourceName != "127.0.0.1" || !strings.Contains(res.Text, "内网通告正文") {
		t.Fatalf("result = %+v", res)
	}
}

func TestExtractTableRowsJSON(t *testing.T) {
	rows := [][]string{
		{"编号", "影响版本", "等级"},
		{"CVE-2026-1", "1.0.0 - 1.2.3", "高"},
		{},
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ExtractTable(raw)
	if err != nil {
		t.Fatalf("extract table: %v", err)
	}
	if res.SourceType != SourceTable {
		t.Fatalf("source type = %q", res.SourceType)
	}
	if !strings.Contains(res.Text, "CVE-2026-1 | 1.0.0 - 1.2.3 | 高") {
		t.Fatalf("text = %q", res.Text)
	}

	objRows := []map[string]string{{"漏洞": "CVE-2026-2", "修复": "升级到 2.0"}}
	raw, _ = json.Marshal(objRows)
	if _, err := ExtractTable(raw); err != nil {
		t.Fatalf("object rows rejected: %v", err)
	}

	if _, err := ExtractTable([]byte(`{"not":"rows"}`)); err == nil {
		t.Fatal("non-row json must be rejected")
	}
}

func TestExtractTruncatesAt256KB(t *testing.T) {
	big := strings.Repeat("字", 120000) // 360KB of UTF-8
	res, err := ExtractFile("big.txt", []byte(big))
	if err != nil {
		t.Fatalf("extract big text: %v", err)
	}
	if !res.Truncated {
		t.Fatal("oversize text must be flagged truncated")
	}
	if len(res.Text) > MaxTextBytes {
		t.Fatalf("text bytes = %d, want <= %d", len(res.Text), MaxTextBytes)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "截断") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v", res.Warnings)
	}

	// Oversize uploads are refused outright.
	if _, err := ExtractFile("huge.txt", make([]byte, MaxInputBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}
// TestExtractEmbeddedState covers the SPA fallback: Next.js / ld+json state
// blobs carry the page body that HTMLToText strips with the other scripts.
func TestExtractEmbeddedState(t *testing.T) {
	html := `<html><head><title>通告</title></head><body>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"title":"某网关命令注入","body":"受影响版本 9.x 的 /api/exec 接口参数 cmd 未过滤，可执行任意系统命令，建议升级到 9.9.10 并临时禁用该接口。","tags":["rce","cwpp"]}}}</script>
<script>window.__INITIAL_STATE__ = {"detail":{"desc":"这是一段足够长的漏洞描述文本，用于验证内嵌状态提取能够恢复正文内容而不是只拿到标题。"}};</script>
</body></html>`
	got := extractEmbeddedState(html)
	if !strings.Contains(got, "受影响版本") || !strings.Contains(got, "漏洞描述") {
		t.Fatalf("embedded state not recovered: %q", got)
	}
}

// TestLooksLikeJSShell pins the shell detection: the JavaScript-required
// boilerplate and script-heavy empty pages are shells; a content page is not.
func TestLooksLikeJSShell(t *testing.T) {
	shell := `<html><body><noscript>We're sorry but app doesn't work properly without JavaScript enabled.</noscript><script src=a.js></script></body></html>`
	if !looksLikeJSShell("奇安信威胁情报中心", shell) {
		t.Fatal("JS shell not detected")
	}
	content := `<html><body><article>` + strings.Repeat("这是一段正常的漏洞通告正文，包含产品、版本、攻击向量与修复建议。", 10) + `</article><script></script></body></html>`
	if looksLikeJSShell(strings.Repeat("正文", 100), content) {
		t.Fatal("content page misdetected as JS shell")
	}
}

// TestErrJSShellMessage keeps the operator-facing guidance in the sentinel.
func TestErrJSShellMessage(t *testing.T) {
	msg := ErrJSShell.Error()
	for _, want := range []string{"SPA", "截图", "粘贴"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("ErrJSShell message missing %q: %s", want, msg)
		}
	}
}
