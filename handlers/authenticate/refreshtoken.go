package authenticate

import (
	"context"
	"time"

	"github.com/g-wilson/seba"
)

func (f *Function) useRefreshToken(ctx context.Context, token string, client seba.Client) (string, string, error) {
	if !client.EnableRefreshTokenGrant {
		return "", "", seba.ErrNotSupportedByClient
	}

	rt, err := f.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(token))
	if err != nil {
		return "", "", err
	}

	if rt.UsedAt != nil {
		return "", "", seba.ErrRefreshTokenUsed
	}

	if rt.ClientID != client.ID {
		return "", "", seba.ErrClientIDMismatch
	}

	if rt.CreatedAt.Add(client.RefreshTokenTTL).Before(time.Now()) {
		return "", "", seba.ErrRefreshTokenExpired
	}

	err = f.Storage.SetRefreshTokenUsed(ctx, rt.ID, rt.UserID)
	if err != nil {
		return "", "", err
	}

	return rt.UserID, rt.GrantID, nil
}
