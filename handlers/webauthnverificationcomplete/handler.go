package webauthnverificationcomplete

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/webauthn"
)

type Function struct {
	Storage     storage.Storage
	Credentials *credentials.Issuer
	Clients     map[string]seba.Client
	Webauthn    webauthn.WebauthnProvider
}

type Request struct {
	ChallengeID       string `json:"challenge_id"`
	AssertionResponse string `json:"assertion_response"`
}

type Response struct {
	*seba.Credentials
}

func (f *Function) Do(ctx context.Context, req *Request) (*Response, error) {
	chal, err := f.Storage.GetWebauthnChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, err
	}

	rt, err := f.Storage.GetRefreshTokenByID(ctx, chal.SessionID)
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

	err = f.Webauthn.CompleteVerification(ctx, chal, req.AssertionResponse)
	if err != nil {
		return nil, err
	}

	err = f.Storage.SetRefreshTokenUsed(ctx, chal.SessionID, rt.UserID)
	if err != nil {
		return nil, err
	}

	user, err := f.Storage.GetUserExtended(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}
	if user.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	creds, err := f.Credentials.Issue(ctx, user, client, rt.GrantID)
	if err != nil {
		return nil, err
	}

	return &Response{&creds}, nil
}
