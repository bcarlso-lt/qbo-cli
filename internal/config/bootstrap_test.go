package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/voska/qbo-cli/internal/errfmt"
)

func writeBootstrap(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QBO_BOOTSTRAP_PATH", path)
}

func TestLoadBootstrapMissing(t *testing.T) {
	t.Setenv("QBO_BOOTSTRAP_PATH", filepath.Join(t.TempDir(), "nope.json"))
	b, ok, err := LoadBootstrap()
	if err != nil || ok || b != nil {
		t.Fatalf("missing file: got b=%v ok=%v err=%v, want nil false nil", b, ok, err)
	}
}

func TestLoadBootstrapValid(t *testing.T) {
	writeBootstrap(t, `{
		"vault_url": "https://v.vault.azure.net",
		"vault_secret_name": "qbo-client-creds",
		"entra_tenant_id": "tenant",
		"entra_client_id": "client"
	}`)
	b, ok, err := LoadBootstrap()
	if err != nil || !ok {
		t.Fatalf("valid file: ok=%v err=%v", ok, err)
	}
	if b.VaultURL != "https://v.vault.azure.net" || b.VaultSecretName != "qbo-client-creds" ||
		b.EntraTenantID != "tenant" || b.EntraClientID != "client" {
		t.Fatalf("unexpected bootstrap: %+v", b)
	}
}

func TestLoadBootstrapInvalidJSON(t *testing.T) {
	writeBootstrap(t, `{not json`)
	_, ok, err := LoadBootstrap()
	if ok || err == nil {
		t.Fatalf("invalid JSON: ok=%v err=%v, want error", ok, err)
	}
	var e *errfmt.Error
	if !errors.As(err, &e) || e.Code != errfmt.ExitConfig {
		t.Fatalf("want ExitConfig error, got %v", err)
	}
}

func TestLoadBootstrapMissingFields(t *testing.T) {
	writeBootstrap(t, `{"vault_url": "https://v.vault.azure.net", "entra_client_id": "client"}`)
	_, ok, err := LoadBootstrap()
	if ok || err == nil {
		t.Fatalf("incomplete file: ok=%v err=%v, want error", ok, err)
	}
	for _, want := range []string{"vault_secret_name", "entra_tenant_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name missing field %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "vault_url,") || strings.Contains(err.Error(), "entra_client_id") {
		t.Errorf("error %q names fields that were present", err)
	}
}

func TestBootstrapPathOverride(t *testing.T) {
	t.Setenv("QBO_BOOTSTRAP_PATH", "/custom/bootstrap.json")
	if got := BootstrapPath(); got != "/custom/bootstrap.json" {
		t.Fatalf("BootstrapPath() = %q", got)
	}
}
