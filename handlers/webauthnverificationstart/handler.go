package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/webauthn"
)

type Handler struct {
	Storage  storage.Storage
	Clients  map[string]seba.Client
	Webauthn webauthn.WebauthnProvider
}

type Request struct {
	RefreshToken string `json:"refresh_token"`
}

type Response struct {
	ChallengeID      string      `json:"challenge_id"`
	AssertionOptions interface{} `json:"assertion_options"`
}

func (h *Handler) Do(ctx context.Context, req *Request) (*Response, error) {
	rt, err := h.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(req.RefreshToken))
	if err != nil {
		return nil, err
	}
	if rt.UsedAt != nil {
		return nil, seba.ErrRefreshTokenUsed
	}

	client, ok := h.Clients[rt.ClientID]
	if !ok {
		return nil, seba.ErrClientNotFound
	}
	if !client.EnableWebauthnVerification {
		return nil, seba.ErrNotSupportedByClient
	}

	res, err := h.Webauthn.StartRegistration(ctx, rt.UserID, rt.ID)
	if err != nil {
		return nil, err
	}

	return &Response{res.Challenge.ID, res.AttestationOptions}, nil
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
