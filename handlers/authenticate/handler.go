package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"

	"github.com/g-wilson/runtime/hand"
)

type Handler struct {
	Token          token.Token
	Storage        storage.Storage
	Credentials    *credentials.Issuer
	Clients        map[string]seba.Client
	GoogleVerifier google.Verifier
}

type Request struct {
	GrantType    string  `json:"grant_type"`
	Code         string  `json:"code"`
	ClientID     string  `json:"client_id"`
	PKCEVerifier *string `json:"pkce_verifier,omitempty"`
}

type Response struct {
	seba.Credentials
}

func (h *Handler) Do(ctx context.Context, req *Request) (res *Response, err error) {
	client, ok := h.Clients[req.ClientID]
	if !ok {
		return nil, seba.ErrClientNotFound
	}

	var userID string
	var rootGrantID string

	switch req.GrantType {
	case seba.GrantTypeEmailToken:
		userID, rootGrantID, err = h.useEmailToken(ctx, req.Code, client, req.PKCEVerifier)
	case seba.GrantTypeRefreshToken:
		userID, rootGrantID, err = h.useRefreshToken(ctx, req.Code, client)
	case seba.GrantTypeGoogle:
		userID, rootGrantID, err = h.useGoogleToken(ctx, req.Code, client)
	default:
		err = seba.ErrUnsupportedGrantType // should not happen
	}
	if err != nil {
		return nil, err
	}

	user, err := h.Storage.GetUserExtended(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	creds, err := h.Credentials.Issue(ctx, user, client, rootGrantID)
	if err != nil {
		return nil, err
	}

	return &Response{Credentials: creds}, nil
}

func (h *Handler) getOrCreateUserByEmail(ctx context.Context, email string) (user seba.User, err error) {
	user, err = h.Storage.CreateUserWithEmail(ctx, email)
	if err != nil {
		if !hand.Matches(err, seba.ErrEmailTaken) {
			return seba.User{}, err
		}

		user, err = h.Storage.GetUserByEmail(ctx, email)
	}

	return
}

func sha256Hex(inputStr string) string {
	digest := sha256.Sum256([]byte(inputStr))
	return hex.EncodeToString(digest[:])
}
