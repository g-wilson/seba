package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/g-wilson/seba"
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

func (g *Generator) CreateRefreshToken(ctx context.Context, user seba.User, client seba.Client, grantID string) (RefreshToken, error) {
	if !client.EnableRefreshTokenGrant {
		return RefreshToken{}, fmt.Errorf("credentials: CreateRefreshToken: client does not allow refresh tokens")
	}

	tok, err := g.token.Generate(32)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("credentials: CreateRefreshToken: %w", err)
	}

	return RefreshToken{
		UserID:   user.ID,
		ClientID: client.ID,
		GrantID:  grantID,
		value:    tok,
	}, nil
}
