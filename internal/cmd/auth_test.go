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

// A provisioned machine without creds must say so, not tell the user to go
// hand-paste org secrets as if the machine were unprovisioned.
func TestLoginWithoutCredsOnProvisionedMachine(t *testing.T) {
	t.Setenv("QBO_CLIENT_ID", "")
	t.Setenv("QBO_CLIENT_SECRET", "")
	g := credsGlobals(&config.Config{}, auth.ClientCreds{}, &config.Bootstrap{VaultURL: "https://v.vault.azure.net"}, nil)
	err := (&AuthLoginCmd{}).Run(g)
	if got := exitCode(err); got != errfmt.ExitConfig {
		t.Fatalf("exit = %d, want %d (%v)", got, errfmt.ExitConfig, err)
	}
	if !strings.Contains(err.Error(), "https://v.vault.azure.net") {
		t.Fatalf("error should name the vault: %v", err)
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
