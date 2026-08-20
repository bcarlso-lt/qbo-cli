package auth

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestFilePasswordFromEnv(t *testing.T) {
	resetFilePassCache(t)
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "hunter2")
	pw, err := filePassword("passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "hunter2" {
		t.Fatalf("got %q, want %q", pw, "hunter2")
	}
}

func TestFilePasswordRejectsSetButEmptyEnv(t *testing.T) {
	resetFilePassCache(t)
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "")
	_, err := filePassword("passphrase")
	if err == nil || !strings.Contains(err.Error(), "set but empty") {
		t.Fatalf("expected set-but-empty error, got: %v", err)
	}
}

func TestFilePasswordFailsHeadlessWithoutEnv(t *testing.T) {
	resetFilePassCache(t)
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "x") // register restore, then unset
	if err := os.Unsetenv("QBO_KEYRING_FILE_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	// Under `go test`, stdin is not a terminal, so the prompt path is
	// unreachable and the missing passphrase must fail, never silently
	// fall back to an empty one.
	if _, err := filePassword("passphrase"); err == nil {
		t.Fatal("expected error when no passphrase source is available")
	}
}

func TestFilePasswordIsCachedPerProcess(t *testing.T) {
	resetFilePassCache(t)
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "first")
	if _, err := filePassword("passphrase"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "second")
	pw, err := filePassword("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if pw != "first" {
		t.Fatalf("expected cached passphrase %q, got %q", "first", pw)
	}
}

func TestStoreTokenFailsWithoutFilePassphrase(t *testing.T) {
	hermeticKeyring(t)
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "")

	err := StoreToken("realm", &oauth2.Token{AccessToken: "x"})
	if err == nil {
		t.Fatal("expected store to fail without a file passphrase")
	}
}

func TestTokenRoundTripWithFilePassphrase(t *testing.T) {
	hermeticKeyring(t)

	want := &oauth2.Token{AccessToken: "access", RefreshToken: "refresh"}
	if err := StoreToken("realm", want); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := LoadToken("realm")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadTokenWrongPassphraseIsConfigErrorNotAuth(t *testing.T) {
	hermeticKeyring(t)

	if err := StoreToken("realm", &oauth2.Token{AccessToken: "x"}); err != nil {
		t.Fatalf("store: %v", err)
	}

	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "wrong-passphrase")
	resetFilePassCache(t)

	_, err := LoadToken("realm")
	if err == nil {
		t.Fatal("expected load with wrong passphrase to fail")
	}
	if strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("wrong passphrase misreported as not authenticated: %v", err)
	}
	if !strings.Contains(err.Error(), "QBO_KEYRING_FILE_PASSWORD") {
		t.Fatalf("error should point at the passphrase: %v", err)
	}
}

func TestLoadTokenMissingEntryIsAuthError(t *testing.T) {
	hermeticKeyring(t)

	_, err := LoadToken("no-such-realm")
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("missing token should be an auth error, got: %v", err)
	}
}
