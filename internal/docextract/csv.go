package docextract

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
)

// charsetReader lets encoding/xml decode non-UTF-8 declarations (the OOXML
// container is UTF-8 by spec, but corrupt exporters emit GBK bytes).
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	return charset.NewReaderLabel(label, input)
}

// decodeCSVBytes normalizes CSV input: a UTF-8 BOM is dropped (otherwise it
// becomes part of the first header cell) and bytes that are not valid UTF-8 are
// decoded as GB18030, the superset of GBK that Chinese spreadsheet exports
// produce. Undecodable input is returned unchanged so the CSV reader reports a
// parse error instead of silently emitting replacement characters.
func decodeCSVBytes(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if utf8.Valid(data) {
		return data
	}
	decoded, cerr := charset.NewReaderLabel("gb18030", bytes.NewReader(data))
	if cerr != nil {
		return data
	}
	out, rerr := io.ReadAll(decoded)
	if rerr != nil || len(out) == 0 || !utf8.Valid(out) {
		return data
	}
	return out
}

// parseCSVRows reads at most maxRows records from a CSV document. Rows parsed
// before a syntax error are returned together with the error so the caller can
// still surface partial content.
func parseCSVRows(data []byte) ([][]string, bool, error) {
	r := csv.NewReader(bytes.NewReader(decodeCSVBytes(data)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = false

	rows := make([][]string, 0, 64)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return rows, false, nil
		}
		if err != nil {
			if len(rows) > 0 {
				return rows, true, fmt.Errorf("CSV 解析在第 %d 行后中断：%w", len(rows)+1, err)
			}
			return nil, false, fmt.Errorf("CSV 解析失败：%w", err)
		}
		if len(rows) >= maxRows {
			return rows, true, nil
		}
		rows = append(rows, rec)
	}
}
