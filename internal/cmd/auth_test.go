package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/voska/qbo-cli/internal/auth"
	"github.com/voska/qbo-cli/internal/config"
	"github.com/voska/qbo-cli/internal/errfmt"
)

// credsGlobals builds a Globals with the lazy keyring and bootstrap loads
// pre-resolved to the given values, so tests never touch the real keychain or
// filesystem.
func credsGlobals(cfg *config.Config, cc auth.ClientCreds, bs *config.Bootstrap, bsErr error) *Globals {
	g := &Globals{Ctx: context.Background(), CLI: &CLI{}, Config: cfg}
	g.ccOnce.Do(func() { g.cc = cc })
	g.bsOnce.Do(func() { g.bs = bs; g.bsErr = bsErr })
	return g
}

func TestClientCredsSourceTiers(t *testing.T) {
	bs := &config.Bootstrap{VaultURL: "https://v.vault.azure.net"}
	cases := []struct {
		name  string
		env   string
		cc    auth.ClientCreds
		cfg   config.Config
		bs    *config.Bootstrap
		bsErr error
		want  string
	}{
		{name: "none", want: "none"},
		{name: "env wins", env: "env-id", cc: auth.ClientCreds{ClientID: "k"}, bs: bs, want: "env"},
		{name: "keyring", cc: auth.ClientCreds{ClientID: "k"}, cfg: config.Config{ClientID: "c"}, want: "keyring"},
		{name: "bootstrap-fetched keyring creds", cc: auth.ClientCreds{ClientID: "k", Origin: auth.CredsOriginBootstrap}, want: "bootstrap"},
		{name: "config file", cfg: config.Config{ClientID: "c"}, bs: bs, want: "config"},
		{name: "provisioned but not yet fetched", bs: bs, want: "bootstrap-pending"},
		{name: "broken bootstrap file", bsErr: errfmt.Config("boom"), want: "bootstrap-error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QBO_CLIENT_ID", tc.env)
			cfg := tc.cfg
			if got := clientCredsSource(credsGlobals(&cfg, tc.cc, tc.bs, tc.bsErr)); got != tc.want {
				t.Fatalf("clientCredsSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A provisioned machine without creds must enter the bootstrap flow, and a
// bootstrap failure must surface through login with its exit code intact.
func TestLoginWithoutCredsOnProvisionedMachineBootstraps(t *testing.T) {
	t.Setenv("QBO_CLIENT_ID", "")
	t.Setenv("QBO_CLIENT_SECRET", "")
	orig := fetchBootstrapCreds
	t.Cleanup(func() { fetchBootstrapCreds = orig })
	fetchBootstrapCreds = func(_ *Globals, b *config.Bootstrap, _, _ bool) (auth.ClientCreds, error) {
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitForbidden, "access denied to "+b.VaultURL)
	}
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, &config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	err := (&AuthLoginCmd{}).Run(g)
	if got := exitCode(err); got != errfmt.ExitForbidden {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitForbidden, err)
	}
	if !strings.Contains(err.Error(), "https://v.vault.azure.net") {
		t.Fatalf("error should name the vault: %v", err)
	}
}

// --dry-run on a provisioned machine must return before any Entra or vault
// network activity.
func TestLoginBootstrapDryRunNoNetwork(t *testing.T) {
	t.Setenv("QBO_CLIENT_ID", "")
	t.Setenv("QBO_CLIENT_SECRET", "")
	orig := fetchBootstrapCreds
	t.Cleanup(func() { fetchBootstrapCreds = orig })
	fetchBootstrapCreds = func(*Globals, *config.Bootstrap, bool, bool) (auth.ClientCreds, error) {
		t.Fatal("dry-run must not fetch")
		return auth.ClientCreds{}, nil
	}
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, &config.Bootstrap{VaultURL: "https://v", VaultSecretName: "s", EntraTenantID: "t", EntraClientID: "c"}, nil)
	g.CLI.DryRun = true
	if err := (&AuthLoginCmd{}).Run(g); err != nil {
		t.Fatalf("dry-run login: %v", err)
	}
}

// A successful vault fetch must persist the creds (marked bootstrap) and
// refresh the memoized keyring creds before the Intuit flow runs, so a later
// Intuit failure or re-store can't lose them or their origin.
func TestBootstrapCredsStoresAndMarksOrigin(t *testing.T) {
	t.Setenv("QBO_KEYRING_BACKEND", "file")
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "test-passphrase")
	t.Setenv("QBO_CONFIG_DIR", t.TempDir())
	orig := fetchBootstrapCreds
	t.Cleanup(func() { fetchBootstrapCreds = orig })
	want := auth.ClientCreds{ClientID: "id", ClientSecret: "sec", Origin: auth.CredsOriginBootstrap}
	fetchBootstrapCreds = func(*Globals, *config.Bootstrap, bool, bool) (auth.ClientCreds, error) {
		return want, nil
	}
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, nil, nil)
	got, err := bootstrapCreds(g, &config.Bootstrap{VaultURL: "https://v"}, false)
	if err != nil || got != want {
		t.Fatalf("bootstrapCreds = %+v, %v", got, err)
	}
	if g.keyringCreds() != want {
		t.Fatalf("memoized creds not refreshed: %+v", g.keyringCreds())
	}
	stored, ok, err := auth.LoadClientCreds()
	if err != nil || !ok || stored != want {
		t.Fatalf("stored = %+v ok=%v err=%v", stored, ok, err)
	}
	if clientCredsSource(g) != "bootstrap" {
		t.Fatalf("source = %q, want bootstrap", clientCredsSource(g))
	}
}

// A fetch failure must propagate its exit code and leave nothing stored.
func TestBootstrapCredsFetchFailure(t *testing.T) {
	t.Setenv("QBO_KEYRING_BACKEND", "file")
	t.Setenv("QBO_KEYRING_FILE_PASSWORD", "test-passphrase")
	t.Setenv("QBO_CONFIG_DIR", t.TempDir())
	orig := fetchBootstrapCreds
	t.Cleanup(func() { fetchBootstrapCreds = orig })
	fetchBootstrapCreds = func(*Globals, *config.Bootstrap, bool, bool) (auth.ClientCreds, error) {
		return auth.ClientCreds{}, errfmt.New(errfmt.ExitForbidden, "denied")
	}
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, nil, nil)
	_, err := bootstrapCreds(g, &config.Bootstrap{VaultURL: "https://v"}, false)
	if got := exitCode(err); got != errfmt.ExitForbidden {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitForbidden, err)
	}
	if _, ok, _ := auth.LoadClientCreds(); ok {
		t.Fatal("failed fetch must not store creds")
	}
}

// A malformed bootstrap file must fail login loudly (exit 10), never read as
// an unprovisioned machine.
func TestLoginSurfacesBrokenBootstrap(t *testing.T) {
	t.Setenv("QBO_CLIENT_ID", "")
	t.Setenv("QBO_CLIENT_SECRET", "")
	want := errfmt.Config("bootstrap config is missing required fields: vault_url")
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, nil, want)
	err := (&AuthLoginCmd{}).Run(g)
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
