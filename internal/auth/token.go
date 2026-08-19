package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/99designs/keyring"
	"github.com/voska/qbo-cli/internal/errfmt"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

const keyringService = "qbo-cli"

// expiryLeeway treats a token as expired slightly before its real expiry so a
// request doesn't go out with a token that lapses mid-flight (mirrors the
// oauth2 library's default expiry delta).
const expiryLeeway = 30 * time.Second

func tokenDir() string {
	if d := os.Getenv("QBO_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "tokens")
	}
	home, err := os.UserConfigDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, "qbo", "tokens")
}

func openKeyring() (keyring.Keyring, error) {
	dir := tokenDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errfmt.Wrap(errfmt.ExitConfig, "cannot create token directory", err)
	}
	cfg := keyring.Config{
		ServiceName:                    keyringService,
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		FileDir:                        dir,
		FilePasswordFunc:               filePassword,
	}
	// QBO_KEYRING_BACKEND=file forces the file backend instead of the OS
	// keychain — useful on headless hosts (e.g. a background daemon that
	// can't reach the login keychain, with QBO_KEYRING_FILE_PASSWORD set)
	// and for hermetic tests. The files are only as protected as the
	// passphrase supplied via filePassword.
	if os.Getenv("QBO_KEYRING_BACKEND") == "file" {
		cfg.AllowedBackends = []keyring.BackendType{keyring.FileBackend}
	}
	return keyring.Open(cfg)
}

// NonInteractive disables the file-backend passphrase prompt. Set from the
// global --no-input flag: never prompt; fail if input would be needed.
var NonInteractive bool

var (
	filePassMu     sync.Mutex
	filePassCached string
)

// filePassword supplies the passphrase for the file backend. It is only
// invoked when that backend is actually selected — forced via
// QBO_KEYRING_BACKEND=file, or the fallback on hosts with no OS keychain.
// An empty passphrase would make the on-disk encryption a no-op, so a real
// one is required: from QBO_KEYRING_FILE_PASSWORD, or an interactive prompt.
// The result is cached for the process so a command that opens the keyring
// several times (load token, load creds, store refreshed token) prompts at
// most once — repeated prompts also risk a mistyped later entry silently
// re-encrypting an entry under a different passphrase.
func filePassword(prompt string) (string, error) {
	filePassMu.Lock()
	defer filePassMu.Unlock()
	if filePassCached != "" {
		return filePassCached, nil
	}
	if pw, set := os.LookupEnv("QBO_KEYRING_FILE_PASSWORD"); set {
		if pw == "" {
			return "", errfmt.Config("QBO_KEYRING_FILE_PASSWORD is set but empty — the file keyring passphrase must not be empty")
		}
		filePassCached = pw
		return pw, nil
	}
	if !NonInteractive && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", errfmt.Config("file keyring passphrase must not be empty")
		}
		filePassCached = string(b)
		return filePassCached, nil
	}
	return "", errfmt.Config("file keyring backend requires a passphrase — set QBO_KEYRING_FILE_PASSWORD")
}

func StoreToken(realmID string, token *oauth2.Token) error {
	kr, err := openKeyring()
	if err != nil {
		return errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	data, err := json.Marshal(token)
	if err != nil {
		return errfmt.Wrap(errfmt.ExitError, "cannot marshal token", err)
	}
	return kr.Set(keyring.Item{
		Key:  realmID,
		Data: data,
	})
}

func LoadToken(realmID string) (*oauth2.Token, error) {
	kr, err := openKeyring()
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	item, err := kr.Get(realmID)
	if errNotFound(err) {
		return nil, errfmt.Auth("not authenticated — run: qbo auth login")
	}
	if err != nil {
		// A decode failure means the entry exists but can't be decrypted:
		// wrong QBO_KEYRING_FILE_PASSWORD, or the entry predates the
		// passphrase requirement (older versions encrypted with an empty
		// passphrase). Don't misreport it as "not authenticated".
		return nil, errfmt.Wrap(errfmt.ExitConfig, "cannot read token from keyring — check QBO_KEYRING_FILE_PASSWORD; tokens stored by older versions must be recreated with: qbo auth login", err)
	}
	var token oauth2.Token
	if err := json.Unmarshal(item.Data, &token); err != nil {
		return nil, errfmt.Wrap(errfmt.ExitConfig, "corrupt token data", err)
	}
	return &token, nil
}

func DeleteToken(realmID string) error {
	kr, err := openKeyring()
	if err != nil {
		return errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	return kr.Remove(realmID)
}

func ListTokenKeys() ([]string, error) {
	kr, err := openKeyring()
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	keys, err := kr.Keys()
	if err != nil {
		return nil, err
	}
	realms := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == clientCredsKey {
			continue
		}
		realms = append(realms, k)
	}
	return realms, nil
}

func IsTokenExpired(token *oauth2.Token) bool {
	return token.Expiry.Add(-expiryLeeway).Before(time.Now())
}
