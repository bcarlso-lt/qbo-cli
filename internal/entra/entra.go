// Package entra acquires Azure Key Vault access tokens via an Entra ID
// sign-in, for the machine-scope bootstrap flow. It uses the pure-Go MSAL
// library (the Azure SDK's persistent cache needs cgo on macOS) with the
// token cache stored in the qbo keyring.
package entra

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/voska/qbo-cli/internal/auth"
	"github.com/voska/qbo-cli/internal/errfmt"
	"github.com/voska/qbo-cli/internal/output"
)

// vaultScope requests a token usable against any Azure Key Vault; RBAC on the
// vault side decides what it can actually read.
const vaultScope = "https://vault.azure.net/.default"

type Options struct {
	TenantID string
	ClientID string
	// DeviceCode prints a code + URL instead of opening a local browser.
	DeviceCode bool
	// NoInput allows only the cached (silent) path; if interaction would be
	// required the sign-in fails with ExitAuth.
	NoInput bool
	// Notify receives user-facing progress lines (e.g. the device-code
	// instructions). Required when DeviceCode is set.
	Notify func(string)
}

// keyringCache adapts the qbo keyring to MSAL's cache interface. Read
// failures degrade to an empty cache with a warning — a corrupt cache should
// cost one extra sign-in, not block login.
type keyringCache struct{}

func (keyringCache) Replace(_ context.Context, u cache.Unmarshaler, _ cache.ReplaceHints) error {
	data, ok, err := auth.LoadEntraCache()
	if err != nil {
		output.Warn("ignoring unreadable Entra token cache: %v", err)
		return nil
	}
	if !ok {
		return nil
	}
	if err := u.Unmarshal(data); err != nil {
		output.Warn("ignoring corrupt Entra token cache: %v", err)
	}
	return nil
}

// Export must never return an error: MSAL aborts the whole acquisition on
// Export failure, which would discard a token that was already successfully
// acquired. A failed cache write costs one extra sign-in next time.
func (keyringCache) Export(_ context.Context, m cache.Marshaler, _ cache.ExportHints) error {
	data, err := m.Marshal()
	if err != nil {
		output.Warn("could not serialize Entra token cache: %v", err)
		return nil
	}
	if err := auth.StoreEntraCache(data); err != nil {
		output.Warn("could not persist Entra token cache (next login will re-prompt): %v", err)
	}
	return nil
}

// AcquireVaultToken signs in to Entra ID and returns a bearer token for Key
// Vault. It tries the cached account silently first, then falls back to an
// interactive browser or device-code flow per opts.
func AcquireVaultToken(ctx context.Context, opts Options) (string, error) {
	client, err := public.New(opts.ClientID,
		public.WithAuthority("https://login.microsoftonline.com/"+opts.TenantID),
		public.WithCache(keyringCache{}),
	)
	if err != nil {
		return "", errfmt.Wrap(errfmt.ExitError, "cannot initialize Entra client", err)
	}
	scopes := []string{vaultScope}

	if accounts, err := client.Accounts(ctx); err == nil && len(accounts) > 0 {
		result, err := client.AcquireTokenSilent(ctx, scopes, public.WithSilentAccount(accounts[0]))
		if err == nil {
			return result.AccessToken, nil
		}
		// Silent failure (expired refresh token, revoked session) falls
		// through to interactive below.
	}

	if opts.NoInput {
		return "", errfmt.New(errfmt.ExitAuth, "Entra sign-in required but --no-input given — run qbo auth login interactively once to cache the sign-in")
	}

	if opts.DeviceCode {
		dc, err := client.AcquireTokenByDeviceCode(ctx, scopes)
		if err != nil {
			return "", classify(err)
		}
		opts.Notify(dc.Result.Message)
		result, err := dc.AuthenticationResult(ctx)
		if err != nil {
			return "", classify(err)
		}
		return result.AccessToken, nil
	}

	result, err := client.AcquireTokenInteractive(ctx, scopes)
	if err != nil {
		return "", classify(err)
	}
	return result.AccessToken, nil
}

// classify maps Entra sign-in failures onto the CLI exit-code contract:
// Conditional Access blocks are permission problems (6), cancellations need a
// re-login (4), transport problems are retryable (8).
func classify(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errfmt.Wrap(errfmt.ExitAuth, "Entra sign-in canceled", err)
	}
	// AADSTS530xx are Conditional Access blocks (unmanaged/non-compliant
	// device); AADSTS50005/50131 are related device-state denials.
	msg := err.Error()
	if strings.Contains(msg, "AADSTS53") || strings.Contains(msg, "AADSTS50131") || strings.Contains(msg, "AADSTS50005") {
		return errfmt.Wrap(errfmt.ExitForbidden, "Entra sign-in blocked by policy: this device must be Intune-enrolled and compliant — contact IT", err)
	}
	if strings.Contains(msg, "AADSTS65004") { // user declined consent
		return errfmt.Wrap(errfmt.ExitAuth, "Entra sign-in declined", err)
	}
	var ne net.Error
	var ue *url.Error
	if errors.As(err, &ne) || errors.As(err, &ue) {
		return errfmt.Wrap(errfmt.ExitRetryable, "cannot reach Entra ID", err)
	}
	return errfmt.Wrap(errfmt.ExitAuth, "Entra sign-in failed", err)
}
