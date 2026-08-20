package auth

import "golang.org/x/oauth2"

const (
	AuthURLProduction  = "https://appcenter.intuit.com/connect/oauth2"
	TokenURLProduction = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
	RevokeURL          = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke"
)

var Scopes = []string{"com.intuit.quickbooks.accounting"}

// tokenURL is a var so tests can point the code exchange at a stub server.
var tokenURL = TokenURLProduction

func OAuthConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURLProduction,
			TokenURL: tokenURL,
		},
	}
}
