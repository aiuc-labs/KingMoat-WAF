package docextract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// extractDOCX reads word/document.xml from the OOXML container: w:p paragraphs
// become lines, w:tbl rows become " | " joined cells, w:t carries the text.
func extractDOCX(data []byte) (string, error) {
	zr, err := newZipReader(data)
	if err != nil {
		return "", fmt.Errorf("无法解析该 Word 文档（文件可能已损坏）")
	}
	f := findZipEntry(zr, "word/document.xml")
	if f == nil {
		return "", fmt.Errorf("无法解析该 Word 文档（缺少 document.xml，可能不是 .docx 文件）")
	}
	raw, err := readZipEntry(f, MaxInputBytes)
	if err != nil {
		return "", fmt.Errorf("无法解析该 Word 文档（读取正文失败）")
	}
	text := docxText(raw)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("未从该 Word 文档中提取到文本内容")
	}
	return text, nil
}

// docxText walks the document body, tracking table/cell/paragraph context.
func docxText(raw []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	dec.CharsetReader = charsetReader

	var (
		b          strings.Builder
		cellCount  int
		tableDepth int
		runText    strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "tbl":
				tableDepth++
				if tableDepth > 1 {
					// Nested tables are flattened into the outer cell.
				}
			case "tr":
				if tableDepth > 0 {
					trimTrailingNewline(&b)
					if b.Len() > 0 {
						b.WriteString("\n")
					}
					cellCount = 0
				}
			case "tc":
				if tableDepth > 0 && cellCount > 0 {
					b.WriteString(" | ")
				}
				cellCount++
			case "p":
				if tableDepth == 0 {
					trimTrailingNewline(&b)
					if b.Len() > 0 {
						b.WriteString("\n")
					}
				}
			case "t":
				var text string
				if err := dec.DecodeElement(&text, &t); err == nil {
					runText.WriteString(text)
					b.WriteString(text)
				}
			case "tab":
				b.WriteString(" ")
			case "br", "cr":
				if tableDepth == 0 {
					b.WriteString("\n")
				} else {
					b.WriteString(" ")
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "tbl":
				if tableDepth > 0 {
					tableDepth--
				}
				trimTrailingNewline(&b)
				b.WriteString("\n")
			case "tr":
				trimTrailingNewline(&b)
			}
		}
	}
	out := strings.TrimSpace(b.String())
	// Collapse runs of blank lines the paragraph/table handling can produce.
	lines := strings.Split(out, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func trimTrailingNewline(b *strings.Builder) {
	s := strings.TrimRight(b.String(), "\n")
	if len(s) == len(b.String()) {
		return
	}
	b.Reset()
	b.WriteString(s)
}

// extractXLSX reads the first worksheet and resolves shared strings.
func extractXLSX(data []byte) (string, error) {
	zr, err := newZipReader(data)
	if err != nil {
		return "", fmt.Errorf("无法解析该 Excel 文档（文件可能已损坏）")
	}
	shared := []string{}
	if f := findZipEntry(zr, "xl/sharedStrings.xml"); f != nil {
		if raw, rerr := readZipEntry(f, MaxInputBytes); rerr == nil {
			shared = parseSharedStrings(raw)
		}
	}
	sheet := firstSheetEntry(zr)
	if sheet == nil {
		return "", fmt.Errorf("无法解析该 Excel 文档（缺少工作表）")
	}
	raw, err := readZipEntry(sheet, MaxInputBytes)
	if err != nil {
		return "", fmt.Errorf("无法解析该 Excel 文档（读取工作表失败）")
	}
	text := sheetText(raw, shared)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("未从该 Excel 文档中提取到文本内容")
	}
	return text, nil
}

type sheetCell struct {
	Type    string `xml:"t,attr"`
	Value   string `xml:"v"`
	Inline  struct {
		Text []string `xml:"t"`
	} `xml:"is"`
}

type sheetRow struct {
	Cells []sheetCell `xml:"c"`
}

func sheetText(raw []byte, shared []string) string {
	var doc struct {
		Rows []sheetRow `xml:"sheetData>row"`
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&doc); err != nil {
		return ""
	}
	var b strings.Builder
	for i, row := range doc.Rows {
		if i >= maxRows {
			break
		}
		cells := make([]string, 0, len(row.Cells))
		for _, c := range row.Cells {
			v := strings.TrimSpace(c.Value)
			switch c.Type {
			case "s":
				if idx, ok := atoiSafe(v); ok && idx >= 0 && idx < len(shared) {
					v = shared[idx]
				}
			case "inlineStr":
				v = strings.TrimSpace(strings.Join(c.Inline.Text, ""))
			}
			v = inlineText(v)
			if v != "" {
				cells = append(cells, v)
			}
		}
		if len(cells) == 0 {
			continue
		}
		b.WriteString(strings.Join(cells, " | "))
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

func parseSharedStrings(raw []byte) []string {
	var doc struct {
		Items []struct {
			Text []string `xml:"t"`
			Runs []struct {
				Text string `xml:"t"`
			} `xml:"r"`
		} `xml:"si"`
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Items))
	for _, it := range doc.Items {
		parts := append([]string{}, it.Text...)
		for _, r := range it.Runs {
			parts = append(parts, r.Text)
		}
		out = append(out, strings.Join(parts, ""))
	}
	return out
}

// extractCSV renders a CSV document as " | " joined rows, bounded to 500 rows.
func extractCSV(data []byte) (string, bool, error) {
	if len(data) > maxCSVBytes {
		data = data[:maxCSVBytes]
	}
	rows, truncated, err := parseCSVRows(data)
	if err != nil {
		return "", false, err
	}
	var b strings.Builder
	for _, row := range rows {
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
	return strings.TrimSpace(b.String()), truncated, nil
}

func newZipReader(data []byte) (*zip.Reader, error) {
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}

func findZipEntry(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, name) {
			return f
		}
	}
	return nil
}

// firstSheetEntry picks sheet1.xml when present, otherwise the first
// worksheets/* entry in lexical order (deterministic for multi-sheet books).
func firstSheetEntry(zr *zip.Reader) *zip.File {
	if f := findZipEntry(zr, "xl/worksheets/sheet1.xml"); f != nil {
		return f
	}
	names := make([]string, 0, len(zr.File))
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		if strings.HasPrefix(strings.ToLower(f.Name), "xl/worksheets/") && strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			names = append(names, f.Name)
			byName[f.Name] = f
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return byName[names[0]]
}

func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	return n, true
}