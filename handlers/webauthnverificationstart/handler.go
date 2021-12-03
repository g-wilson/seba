package webauthnverificationstart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/webauthn"
)

type Function struct {
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

func (f *Function) Do(ctx context.Context, req *Request) (*Response, error) {
	rt, err := f.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(req.RefreshToken))
	if err != nil {
		return nil, err
	}
	if rt.UsedAt != nil {
		return nil, seba.ErrRefreshTokenUsed
	}

	client, ok := f.Clients[rt.ClientID]
	if !ok {
		return nil, seba.ErrClientNotFound
	}
	if !client.EnableAccessTokenElevation {
		return nil, seba.ErrNotSupportedByClient
	}

	res, err := f.Webauthn.StartRegistration(ctx, rt.UserID, rt.ID)
	if err != nil {
		return nil, err
	}

	return &Response{res.Challenge.ID, res.AttestationOptions}, nil
}

func sha256Hex(inputStr string) string {
	digest := sha256.Sum256([]byte(inputStr))
	return hex.EncodeToString(digest[:])
}
