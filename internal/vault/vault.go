// Package vault fetches the org's OAuth client credentials from an Azure Key
// Vault secret. It is a single authenticated REST GET rather than the Azure
// SDK: the SDK's credential chain and persistent cache assume cgo on macOS,
// and one secret read doesn't justify the dependency tree.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/voska/qbo-cli/internal/auth"
	"github.com/voska/qbo-cli/internal/errfmt"
)

const apiVersion = "7.4"

// checkVaultURL guards where the bearer token goes: bootstrap.json is
// machine-scope but not beyond tampering, and the token is valid for every
// vault the user can access — it must never be attached to a request leaving
// for an arbitrary (or cleartext) host. A package var so tests can point at a
// local fake vault.
var checkVaultURL = validateVaultURL

// vaultHostSuffixes are the Key Vault DNS suffixes across Azure clouds.
var vaultHostSuffixes = []string{
	".vault.azure.net",
	".vault.azure.cn",
	".vault.usgovcloudapi.net",
	".vault.microsoftazure.de",
	".managedhsm.azure.net",
}

func validateVaultURL(vaultURL string) error {
	u, err := url.Parse(vaultURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errfmt.New(errfmt.ExitConfig, "vault_url must be an https Azure Key Vault URL, got "+vaultURL)
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range vaultHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return errfmt.New(errfmt.ExitConfig, "vault_url host "+host+" is not an Azure Key Vault — refusing to send credentials to it")
}

// FetchClientCreds reads the named secret and parses it as client-credential
// JSON ({"client_id": ..., "client_secret": ..., "redirect_uri"?: ...}).
// The returned creds are marked Origin=bootstrap.
func FetchClientCreds(ctx context.Context, client *http.Client, vaultURL, secretName, bearer string) (auth.ClientCreds, error) {
	if err := checkVaultURL(vaultURL); err != nil {
		return auth.ClientCreds{}, err
	}
	secretURL := strings.TrimSuffix(vaultURL, "/") + "/secrets/" + url.PathEscape(secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secretURL+"?api-version="+apiVersion, nil)
	if err != nil {
		return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitError, "cannot build vault request", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitAuth, "vault fetch canceled", err)
		}
		// DeadlineExceeded here is the bounded HTTP client tripping on a
		// stalled connection (the process context has no deadline) — a
		// transport failure, retryable like the path below.
		return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitRetryable, "cannot reach key vault "+vaultURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitRetryable, "cannot read vault response", err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitForbidden, "access denied to "+secretURL+" — ask IT to grant your account access to the qbo credentials secret")
	case resp.StatusCode == http.StatusNotFound:
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitConfig, "secret not found at "+secretURL+" — the vault is misprovisioned, contact IT")
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitRetryable, "key vault returned "+resp.Status+" for "+secretURL)
	default:
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitError, "key vault returned "+resp.Status+" for "+secretURL)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitError, "unexpected vault response for "+secretURL, err)
	}
	return parseClientCreds(payload.Value, secretURL)
}

// parseClientCreds validates the secret's content. Malformed content is a
// provisioning error (exit 10) and must never be stored.
func parseClientCreds(value, secretURL string) (auth.ClientCreds, error) {
	var c auth.ClientCreds
	if err := json.Unmarshal([]byte(value), &c); err != nil {
		return auth.ClientCreds{}, errfmt.Wrap(errfmt.ExitConfig, "secret at "+secretURL+" is not client-credential JSON — the vault is misprovisioned, contact IT", err)
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitConfig, "secret at "+secretURL+" is missing client_id or client_secret — the vault is misprovisioned, contact IT")
	}
	c.Origin = auth.CredsOriginBootstrap
	return c, nil
}
