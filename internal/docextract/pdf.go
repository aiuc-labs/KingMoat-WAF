package docextract

import (
	"bytes"
	"errors"
	"strings"

	"github.com/ledongthuc/pdf"
)

// extractPDF reads the text layer page by page. The page walk is capped
// (maxPDFPages) and every page is decoded defensively: a single broken page
// must not fail the whole advisory.
func extractPDF(data []byte) (text string, err error) {
	if len(data) < 8 {
		return "", ErrPDFBroken
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("%PDF")) {
		return "", ErrPDFBroken
	}
	// The third-party parser dereferences structures it trusts; a panic on a
	// malformed file is converted into a user-facing parse error rather than
	// taking the console down.
	defer func() {
		if rec := recover(); rec != nil {
			text = ""
			err = ErrPDFBroken
		}
	}()

	reader, oerr := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if oerr != nil {
		// Only a password error means "encrypted"; everything else (truncated,
		// unsupported cross-reference) is a broken file and is reported as such,
		// otherwise the console tells the operator to fix the wrong thing.
		if errors.Is(oerr, pdf.ErrInvalidPassword) {
			return "", ErrPDFEncrypted
		}
		return "", ErrPDFBroken
	}
	pages := reader.NumPage()
	if pages <= 0 {
		return "", ErrPDFNoText
	}
	if pages > maxPDFPages {
		pages = maxPDFPages
	}
	var b strings.Builder
	for i := 1; i <= pages; i++ {
		page := reader.Page(i)
		if page.V.IsNull() {
			continue
		}
		pageText, perr := page.GetPlainText(nil)
		if perr != nil {
			if errors.Is(perr, pdf.ErrInvalidPassword) {
				return "", ErrPDFEncrypted
			}
			continue
		}
		b.WriteString(pageText)
		b.WriteString("\n")
		if b.Len() > MaxTextBytes*2 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", ErrPDFNoText
	}
	return out, nil
}
