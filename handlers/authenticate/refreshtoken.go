package main

import (
	"context"
	"time"

	"github.com/g-wilson/seba"
)

func (h *Handler) useRefreshToken(ctx context.Context, token string, client seba.Client) (string, string, error) {
	if !client.EnableRefreshTokenGrant {
		return "", "", seba.ErrNotSupportedByClient
	}

	rt, err := h.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(token))
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

	err = h.Storage.SetRefreshTokenUsed(ctx, rt.ID, rt.UserID)
	if err != nil {
		return "", "", err
	}

	return rt.UserID, rt.GrantID, nil
}
