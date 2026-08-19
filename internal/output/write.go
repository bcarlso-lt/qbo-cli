package output

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func Write(ctx context.Context, data any) error {
	opts := GetOptions(ctx)

	if opts.ResultsOnly {
		data = StripMetadata(data)
	}
	if len(opts.Select) > 0 {
		data = ProjectFields(data, opts.Select)
	}

	switch opts.Mode {
	case ModeJSON:
		return WriteJSON(data, opts.Pretty)
	case ModePlain:
		headers, rows := toTable(data)
		WritePlain(headers, rows)
		return nil
	default:
		headers, rows := toTable(data)
		WriteTable(headers, rows)
		return nil
	}
}

func normalize(data any) any {
	switch data.(type) {
	case map[string]any, []any:
		return data
	default:
		b, err := json.Marshal(data)
		if err != nil {
			return data
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			return data
		}
		return out
	}
}

func toTable(data any) ([]string, [][]string) {
	data = normalize(data)
	switch v := data.(type) {
	case []any:
		if len(v) == 0 {
			return nil, nil
		}
		headers := collectHeaders(v)
		rows := make([][]string, len(v))
		for i, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				rows[i] = []string{cell(item)}
				continue
			}
			row := make([]string, len(headers))
			for j, h := range headers {
				if val, ok := m[h]; ok {
					row[j] = cell(val)
				}
			}
			rows[i] = row
		}
		return sanitizeHeaders(headers), rows
	case map[string]any:
		headers := sortedKeys(v)
		row := make([]string, len(headers))
		for i, h := range headers {
			row[i] = cell(v[h])
		}
		return sanitizeHeaders(headers), [][]string{row}
	default:
		return nil, [][]string{{cell(data)}}
	}
}

// cell renders a value for human/plain output. API-sourced strings are
// untrusted (customer names, memos, and line descriptions are routinely
// populated by external parties), so control characters are removed: an
// embedded ESC/CSI/OSC sequence could rewrite or spoof terminal output, and
// an embedded newline or tab would forge extra table rows or TSV columns.
// JSON mode is unaffected — encoding/json escapes control characters itself.
func cell(val any) string {
	return sanitizeCell(fmt.Sprint(val))
}

// sanitizeHeaders applies cell sanitization to header labels for display.
// Row values are looked up under the original (unsanitized) keys before this
// runs, so a hostile key only changes how the column is labeled, never which
// values land in it.
func sanitizeHeaders(headers []string) []string {
	out := make([]string, len(headers))
	for i, h := range headers {
		out[i] = sanitizeCell(h)
	}
	return out
}

func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return sanitizeRune(r)
	}, s)
}

// SanitizeMessage cleans untrusted text destined for stderr status lines
// (hints, warnings, error details that may embed raw API response bodies).
// Unlike table cells, newlines and tabs are legitimate message formatting
// and pass through.
func SanitizeMessage(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		return sanitizeRune(r)
	}, s)
}

// sanitizeRune drops characters that can rewrite, reorder, or invisibly
// alter terminal output; everything else passes through unchanged.
func sanitizeRune(r rune) rune {
	switch {
	case r < 0x20 || r == 0x7f: // C0 controls + DEL (includes ESC)
		return -1
	case r >= 0x80 && r <= 0x9f: // C1 controls (8-bit CSI/OSC forms)
		return -1
	case r == 0x2028 || r == 0x2029: // line/paragraph separators
		return ' '
	case r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff: // zero-width
		return -1
	case r == 0x200e || r == 0x200f || r == 0x061c: // bidi marks
		return -1
	case r >= 0x202a && r <= 0x202e: // bidi embedding/override
		return -1
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return -1
	}
	return r
}

func collectHeaders(items []any) []string {
	seen := map[string]bool{}
	var headers []string
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for k := range m {
			if !seen[k] {
				seen[k] = true
				headers = append(headers, k)
			}
		}
	}
	sort.Strings(headers)
	return headers
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
