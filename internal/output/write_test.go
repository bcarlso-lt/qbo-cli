package output

import (
	"strings"
	"testing"
)

func TestSanitizeCellStripsANSIEscapes(t *testing.T) {
	got := sanitizeCell("Acme\x1b[2K\x1b[1A Corp")
	if got != "Acme[2K[1A Corp" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeCellStripsOSC(t *testing.T) {
	got := sanitizeCell("evil\x1b]0;spoofed title\x07vendor")
	if got != "evil]0;spoofed titlevendor" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeCellStripsC1Controls(t *testing.T) {
	// U+009B is the single-rune C1 CSI: it acts like ESC-[ on terminals
	// that honor 8-bit controls.
	got := sanitizeCell("ven\u009b31mdor")
	if got != "ven31mdor" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeCellFlattensLineBreaksAndTabs(t *testing.T) {
	got := sanitizeCell("line1\nline2\tcol\rmore sep")
	if got != "line1 line2 col more sep" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeCellStripsBidiAndZeroWidth(t *testing.T) {
	in := "Acme \u202e00.9$ dnufeR\u202c end\u200bzw\ufeff before\u2028after"
	got := sanitizeCell(in)
	if got != "Acme 00.9$ dnufeR endzw before after" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeCellPassesPlainText(t *testing.T) {
	in := "Åcme & Söns — 100% legit café ✓"
	if got := sanitizeCell(in); got != in {
		t.Fatalf("mangled clean text: %q -> %q", in, got)
	}
}

func TestSanitizeMessageKeepsNewlinesStripsEscapes(t *testing.T) {
	got := SanitizeMessage("line1\nline2\t\x1b[2Jrest\u009bx")
	if got != "line1\nline2\t[2Jrestx" {
		t.Fatalf("got %q", got)
	}
}

func TestToTableSanitizesValues(t *testing.T) {
	headers, rows := toTable([]any{
		map[string]any{"DisplayName": "Acme\x1b[8m hidden", "Balance": 100.5},
	})
	if len(headers) != 2 || len(rows) != 1 {
		t.Fatalf("unexpected shape: %v %v", headers, rows)
	}
	for _, cell := range rows[0] {
		if strings.ContainsRune(cell, 0x1b) {
			t.Fatalf("ESC reached table cell: %q", cell)
		}
	}
}

func TestToTableSanitizesHeaders(t *testing.T) {
	headers, rows := toTable([]any{
		map[string]any{"Name\x1b[2J": "a", "Memo\tX": "b"},
	})
	for _, h := range headers {
		if strings.ContainsRune(h, 0x1b) || strings.ContainsRune(h, '\t') {
			t.Fatalf("unsanitized header: %q", h)
		}
	}
	// Row values must still be found under the original hostile keys.
	joined := strings.Join(rows[0], "|")
	if !strings.Contains(joined, "a") || !strings.Contains(joined, "b") {
		t.Fatalf("row lookup broke under sanitized headers: %v", rows)
	}

	_, rows2 := toTable(map[string]any{"Key\x1b[1A": "val"})
	if len(rows2) != 1 || rows2[0][0] != "val" {
		t.Fatalf("single-object row lookup broke: %v", rows2)
	}
}

func TestToTableSanitizesSingleObjectAndScalar(t *testing.T) {
	_, rows := toTable(map[string]any{"Memo": "pay\x1b[1A me"})
	if strings.ContainsRune(rows[0][0], 0x1b) {
		t.Fatalf("ESC in object row: %q", rows[0][0])
	}
	_, rows = toTable("raw\x1b[2Jstring")
	if strings.ContainsRune(rows[0][0], 0x1b) {
		t.Fatalf("ESC in scalar row: %q", rows[0][0])
	}
}
