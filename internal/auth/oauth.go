package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/voska/qbo-cli/internal/errfmt"
	"golang.org/x/oauth2"
)

// loginTimeout bounds the local browser-callback login so an abandoned login
// releases the callback port instead of hanging forever.
const loginTimeout = 5 * time.Minute

type AuthResult struct {
	Token   *oauth2.Token
	RealmID string
}

func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errfmt.Wrap(errfmt.ExitError, "cannot generate secure OAuth state", err)
	}
	return hex.EncodeToString(b), nil
}

func GetAuthURL(clientID, clientSecret, redirectURL, state string) string {
	cfg := OAuthConfig(clientID, clientSecret, redirectURL)
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func ExchangeCode(ctx context.Context, clientID, clientSecret, redirectURL, code string) (*oauth2.Token, error) {
	cfg := OAuthConfig(clientID, clientSecret, redirectURL)
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitAuth, "token exchange failed", err)
	}
	return token, nil
}

func RefreshAccessToken(ctx context.Context, clientID, clientSecret string, token *oauth2.Token) (*oauth2.Token, error) {
	cfg := OAuthConfig(clientID, clientSecret, "")
	src := cfg.TokenSource(ctx, token)
	newToken, err := src.Token()
	if err != nil {
		wrapped := errfmt.Wrap(errfmt.ExitAuth, "token refresh failed", err)
		// Classify while the typed oauth2 error is still in hand — errfmt
		// flattens the chain to a string.
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_client" {
			return nil, &InvalidClientError{Err: wrapped}
		}
		return nil, wrapped
	}
	return newToken, nil
}

// InvalidClientError marks a refresh that Intuit rejected because the client
// credentials themselves are bad (rotated or revoked app secret), as opposed
// to a dead refresh token. The vault self-heal keys off this type.
type InvalidClientError struct{ Err *errfmt.Error }

func (e *InvalidClientError) Error() string { return e.Err.Error() }
func (e *InvalidClientError) Unwrap() error { return e.Err }

// IsInvalidClient reports whether err (anywhere in its chain) is an
// InvalidClientError.
func IsInvalidClient(err error) bool {
	var ice *InvalidClientError
	return errors.As(err, &ice)
}

const DefaultCallbackPort = 8844

func DefaultRedirectURI() string {
	return fmt.Sprintf("http://localhost:%d/callback", DefaultCallbackPort)
}

func isLocalRedirect(redirectURL string) bool {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// LoginInteractive runs the browser OAuth flow, listening on
// localhost:8844 for the callback regardless of the registered redirect URI.
// A non-local redirectURL is "bouncer mode": Intuit requires HTTPS redirect
// URIs on production apps, so a hosted static page receives the callback and
// forwards it (query string intact) to the local listener. manual selects the
// paste-the-callback-URL flow instead, which requires an interactive stdin.
func LoginInteractive(ctx context.Context, clientID, clientSecret, redirectURL string, manual bool) (*AuthResult, error) {
	if redirectURL == "" {
		redirectURL = DefaultRedirectURI()
	}

	if manual {
		return loginManual(ctx, clientID, clientSecret, redirectURL)
	}
	return loginListen(ctx, clientID, clientSecret, redirectURL)
}

func loginListen(ctx context.Context, clientID, clientSecret, redirectURL string) (*AuthResult, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	addr := fmt.Sprintf("127.0.0.1:%d", DefaultCallbackPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitError, fmt.Sprintf("cannot listen on port %d — is another qbo login running?", DefaultCallbackPort), err)
	}

	cfg := OAuthConfig(clientID, clientSecret, redirectURL)
	state, err := GenerateState()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	resultCh := make(chan *AuthResult, 1)
	errCh := make(chan error, 1)

	// The response must be written and flushed before signaling the channels:
	// a signal makes loginListen return and Close the server, which kills the
	// connection before an unflushed response reaches the browser.
	flush := func(w http.ResponseWriter) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			flush(w)
			errCh <- errfmt.New(errfmt.ExitAuth, "state mismatch")
			return
		}
		code := r.URL.Query().Get("code")
		realmID := r.URL.Query().Get("realmId")
		if code == "" || realmID == "" {
			http.Error(w, "missing parameters", http.StatusBadRequest)
			flush(w)
			errCh <- errfmt.New(errfmt.ExitAuth, "missing code or realmId")
			return
		}
		token, terr := cfg.Exchange(ctx, code)
		if terr != nil {
			http.Error(w, "exchange failed", http.StatusInternalServerError)
			flush(w)
			errCh <- errfmt.Wrap(errfmt.ExitAuth, "token exchange failed", terr)
			return
		}
		_, _ = fmt.Fprint(w, "<html><body><h2>Authenticated!</h2><p>You can close this window.</p></body></html>")
		flush(w)
		resultCh <- &AuthResult{Token: token, RealmID: realmID}
	})

	server := &http.Server{Handler: mux}
	go func() {
		if serr := server.Serve(listener); serr != http.ErrServerClosed {
			errCh <- serr
		}
	}()
	defer func() { _ = server.Close() }()

	authURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Fprintf(os.Stderr, "Open this URL in your browser:\n\n  %s\n\n", authURL)
	if !isLocalRedirect(redirectURL) {
		fmt.Fprintf(os.Stderr, "The callback will bounce through %s back to this machine.\n", redirectURL)
	}
	openBrowser(authURL)

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, errfmt.New(errfmt.ExitAuth, "login timed out")
	}
}

func loginManual(ctx context.Context, clientID, clientSecret, redirectURL string) (*AuthResult, error) {
	cfg := OAuthConfig(clientID, clientSecret, redirectURL)
	state, err := GenerateState()
	if err != nil {
		return nil, err
	}

	authURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Fprintf(os.Stderr, "Open this URL in your browser:\n\n  %s\n\n", authURL)
	fmt.Fprintf(os.Stderr, "After authorizing, paste the full callback URL here:\n")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil, errfmt.New(errfmt.ExitAuth, "no input received")
	}
	callbackURL := strings.TrimSpace(scanner.Text())
	if callbackURL == "" {
		return nil, errfmt.New(errfmt.ExitAuth, "empty callback URL")
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitAuth, "invalid callback URL", err)
	}

	q := u.Query()
	if q.Get("state") != state {
		return nil, errfmt.New(errfmt.ExitAuth, "state mismatch — possible CSRF attack or stale URL")
	}

	code := q.Get("code")
	realmID := q.Get("realmId")
	if code == "" || realmID == "" {
		return nil, errfmt.New(errfmt.ExitAuth, "callback URL missing code or realmId parameters")
	}

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, errfmt.Wrap(errfmt.ExitAuth, "token exchange failed", err)
	}

	return &AuthResult{Token: token, RealmID: realmID}, nil
}

// openBrowser is a var so tests can capture the auth URL instead of opening
// a real browser.
var openBrowser = func(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}
	_ = cmd.Start()
}
