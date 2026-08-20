package entra

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/voska/qbo-cli/internal/errfmt"
)

func classifiedCode(t *testing.T, err error) int {
	t.Helper()
	var e *errfmt.Error
	if !errors.As(classify(err), &e) {
		t.Fatalf("classify returned non-errfmt error: %v", err)
	}
	return e.Code
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"conditional access block", errors.New(`AADSTS530003: Your device is required to be managed`), errfmt.ExitForbidden},
		{"device state denial", errors.New(`AADSTS50131: Device is not in required state`), errfmt.ExitForbidden},
		{"platform blocked", errors.New(`AADSTS50005: Device platform is not supported by policy`), errfmt.ExitForbidden},
		{"declined consent", errors.New(`AADSTS65004: User declined to consent`), errfmt.ExitAuth},
		{"canceled", context.Canceled, errfmt.ExitAuth},
		{"timed out", context.DeadlineExceeded, errfmt.ExitAuth},
		{"network", &url.Error{Op: "Get", URL: "https://login.microsoftonline.com", Err: errors.New("connection refused")}, errfmt.ExitRetryable},
		{"generic", errors.New("something else"), errfmt.ExitAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifiedCode(t, tc.err); got != tc.want {
				t.Fatalf("classify(%v) exit = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

type fakeCacheData struct{ data []byte }

func (f *fakeCacheData) Marshal() ([]byte, error) { return f.data, nil }
func (f *fakeCacheData) Unmarshal(b []byte) error { f.data = append([]byte(nil), b...); return nil }

// The keyring-backed MSAL cache must round-trip bytes and treat a missing
// entry as an empty cache.
func TestKeyringCacheRoundTrip(t *testing.T) {
	t.Setenv("QBO_KEYRING_BACKEND", "file")
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "test-passphrase")
	t.Setenv("QBO_CONFIG_DIR", t.TempDir())

	c := keyringCache{}
	empty := &fakeCacheData{data: []byte("sentinel")}
	if err := c.Replace(context.Background(), empty, cache.ReplaceHints{}); err != nil {
		t.Fatalf("Replace on empty cache: %v", err)
	}
	if string(empty.data) != "sentinel" {
		t.Fatalf("Replace overwrote cache despite no stored entry: %q", empty.data)
	}

	if err := c.Export(context.Background(), &fakeCacheData{data: []byte("msal-cache-bytes")}, cache.ExportHints{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	loaded := &fakeCacheData{}
	if err := c.Replace(context.Background(), loaded, cache.ReplaceHints{}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if string(loaded.data) != "msal-cache-bytes" {
		t.Fatalf("round-trip = %q", loaded.data)
	}
}
