package credentials

import (
	"crypto/sha256"
	"encoding/hex"
)

type RefreshToken struct {
	UserID   string
	ClientID string
	GrantID  string

	value string
}

func (t *RefreshToken) Value() string {
	return t.value
}

func (t *RefreshToken) HashedValue() string {
	digest := sha256.Sum256([]byte(t.value))

	return hex.EncodeToString(digest[:])
}
