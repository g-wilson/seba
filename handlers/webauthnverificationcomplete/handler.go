package main

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/webauthn"
)

type Handler struct {
	Storage     storage.Storage
	Credentials credentials.CredentialProvider
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

func (h *Handler) Do(ctx context.Context, req *Request) (*Response, error) {
	chal, err := h.Storage.GetWebauthnChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, err
	}

	rt, err := h.Storage.GetRefreshTokenByID(ctx, chal.SessionID)
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

	err = h.Webauthn.CompleteVerification(ctx, chal, req.AssertionResponse)
	if err != nil {
		return nil, err
	}

	user, err := h.Storage.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	tokens, err := h.Credentials.CreateForUserElevated(ctx, user, client, rt.AuthenticationID)
	if err != nil {
		return nil, err
	}

	err = h.Storage.SetRefreshTokenUsed(ctx, chal.SessionID, rt.UserID)
	if err != nil {
		return nil, err
	}

	return &Response{tokens}, nil
}