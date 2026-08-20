package config

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"

	"github.com/voska/qbo-cli/internal/errfmt"
)

// Bootstrap is machine-scope provisioning config installed by an org's device
// management (e.g. an Intune .pkg). It carries no secrets — only the pointers
// a first `qbo auth login` needs to fetch the OAuth client credentials from
// Azure Key Vault after an Entra ID sign-in. Its presence forms the lowest
// tier of client-credential resolution, below env, keyring, and config file,
// so the binary itself stays org-agnostic.
type Bootstrap struct {
	// VaultURL is the Azure Key Vault base URL, e.g. https://myvault.vault.azure.net.
	VaultURL string `json:"vault_url"`
	// VaultSecretName names the Key Vault secret holding the client
	// credentials JSON ({"client_id": ..., "client_secret": ...}).
	VaultSecretName string `json:"vault_secret_name"`
	// EntraTenantID is the Entra ID (Azure AD) tenant to authenticate against.
	EntraTenantID string `json:"entra_tenant_id"`
	// EntraClientID is the Entra app registration used for the sign-in that
	// authorizes the Key Vault read.
	EntraClientID string `json:"entra_client_id"`
}

// BootstrapPath returns the machine-scope bootstrap file location, or the
// QBO_BOOTSTRAP_PATH override when set.
func BootstrapPath() string {
	if p := os.Getenv("QBO_BOOTSTRAP_PATH"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/qbo/bootstrap.json"
	case "windows":
		return `C:\ProgramData\qbo\bootstrap.json`
	default:
		return "/etc/qbo/bootstrap.json"
	}
}

// LoadBootstrap reads the machine-scope bootstrap config. The bool reports
// whether the file existed; a missing file is not an error since most
// installs are not org-provisioned. A file that exists but is malformed or
// incomplete is a config error — a half-provisioned machine should fail
// loudly, not silently degrade to "no credentials".
func LoadBootstrap() (*Bootstrap, bool, error) {
	path := BootstrapPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errfmt.Wrap(errfmt.ExitConfig, "cannot read bootstrap config "+path, err)
	}
	var b Bootstrap
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, false, errfmt.Wrap(errfmt.ExitConfig, "invalid bootstrap config "+path, err)
	}
	var missing []string
	for _, f := range []struct{ name, val string }{
		{"vault_url", b.VaultURL},
		{"vault_secret_name", b.VaultSecretName},
		{"entra_tenant_id", b.EntraTenantID},
		{"entra_client_id", b.EntraClientID},
	} {
		if f.val == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return nil, false, errfmt.Config("bootstrap config " + path + " is missing required fields: " + strings.Join(missing, ", "))
	}
	return &b, true, nil
}
