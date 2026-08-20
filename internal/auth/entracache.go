package auth

import (
	"github.com/99designs/keyring"
	"github.com/voska/qbo-cli/internal/errfmt"
)

// entraCacheKey is the reserved keyring entry holding the opaque MSAL token
// cache for the Entra ID sign-in used by the vault bootstrap flow. Like
// clientCredsKey, the hyphenated name never collides with numeric realm IDs.
const entraCacheKey = "entra-msal-cache"

// StoreEntraCache persists the serialized MSAL token cache.
func StoreEntraCache(data []byte) error {
	kr, err := openKeyring()
	if err != nil {
		return errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	return kr.Set(keyring.Item{Key: entraCacheKey, Data: data})
}

// LoadEntraCache returns the serialized MSAL token cache. The bool reports
// whether an entry existed; a missing entry is not an error — it just means
// no Entra sign-in has been cached yet.
func LoadEntraCache() ([]byte, bool, error) {
	kr, err := openKeyring()
	if err != nil {
		return nil, false, errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	item, err := kr.Get(entraCacheKey)
	if errNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errfmt.Wrap(errfmt.ExitConfig, "cannot read Entra token cache", err)
	}
	return item.Data, true, nil
}

// DeleteEntraCache removes the cached Entra sign-in, if any.
func DeleteEntraCache() error {
	kr, err := openKeyring()
	if err != nil {
		return errfmt.Wrap(errfmt.ExitConfig, "cannot open keyring", err)
	}
	if err := kr.Remove(entraCacheKey); err != nil && !errNotFound(err) {
		return errfmt.Wrap(errfmt.ExitConfig, "cannot remove Entra token cache", err)
	}
	return nil
}
