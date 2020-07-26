package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/g-wilson/seba"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Authenticate is the RPC handler for authentication endpoint
func (a *App) Authenticate(ctx context.Context, req *seba.AuthenticateRequest) (res *seba.AuthenticateResponse, err error) {
	client, ok := a.clientsByID[req.ClientID]
	if !ok {
		return nil, seba.ErrClientNotFound
	}

	var creds *seba.Credentials

	switch req.GrantType {
	case seba.GrantTypeEmailToken:
		creds, err = a.useEmailToken(ctx, req.Code, client, req.PKCEVerifier)
	case seba.GrantTypeRefreshToken:
		creds, err = a.useRefreshToken(ctx, req.Code, client)
	case seba.GrantTypeGoogle:
		creds, err = a.useGoogleToken(ctx, req.Code, client)
	default:
		err = seba.ErrUnsupportedGrantType // should not happen
	}
	if err != nil {
		return nil, err
	}

	return &seba.AuthenticateResponse{Credentials: creds}, nil
}

func (a *App) useEmailToken(ctx context.Context, token string, client seba.Client, verifier *string) (creds *seba.Credentials, err error) {
	if !client.EmailGrantEnabled() {
		return nil, seba.ErrNotSupportedByClient
	}

	if verifier == nil {
		return nil, seba.ErrPKCEVerifierRequired
	}

	authn, err := a.Storage.GetAuthenticationByHashedCode(ctx, sha256Hex(token))
	if err != nil {
		return nil, err
	}
	if authn.ClientID != client.ID {
		return nil, seba.ErrClientIDMismatch
	}
	if authn.CreatedAt.Add(5 * time.Minute).Before(time.Now()) {
		return nil, seba.ErrAuthnExpired
	}
	if authn.VerifiedAt != nil {
		return nil, seba.ErrAuthnAlreadyVerified
	}
	if authn.RevokedAt != nil {
		return nil, seba.ErrAuthnRevoked
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(authn.PKCEChallenge)
	if err != nil {
		return nil, err
	}

	hashedVerifier := sha256.Sum256([]byte(*verifier))

	if subtle.ConstantTimeCompare(hashedVerifier[:], challengeBytes) != 1 {
		return nil, seba.ErrPKCEChallengeFailed
	}

	user, err := a.Storage.GetUserByEmail(ctx, authn.Email)
	if err != nil {
		return nil, err
	}

	creds, err = a.CreateUserCredentials(ctx, user, client, &authn.ID)
	if err != nil {
		return nil, err
	}

	err = a.Storage.SetAuthenticationVerified(ctx, authn.ID, authn.Email)

	return
}

func (a *App) useRefreshToken(ctx context.Context, token string, client seba.Client) (*seba.Credentials, error) {
	if !client.RefreshGrantEnabed() {
		return nil, seba.ErrNotSupportedByClient
	}

	rt, err := a.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(token))
	if err != nil {
		return nil, err
	}

	if rt.UsedAt != nil {
		return nil, seba.ErrRefreshTokenUsed
	}

	if rt.ClientID != client.ID {
		return nil, seba.ErrClientIDMismatch
	}

	if rt.CreatedAt.Add(client.RefreshTokenTTL).Before(time.Now()) {
		return nil, seba.ErrRefreshTokenExpired
	}

	user, err := a.Storage.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	creds, err := a.CreateUserCredentials(ctx, user, client, rt.AuthenticationID)
	if err != nil {
		return nil, err
	}

	err = a.Storage.SetRefreshTokenUsed(ctx, rt.ID, user.ID)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func (a *App) useGoogleToken(ctx context.Context, code string, client seba.Client) (*seba.Credentials, error) {
	if !client.GoogleGrantEnabled() {
		return nil, seba.ErrNotSupportedByClient
	}

	gResp, err := client.GoogleConfig.Exchange(ctx, code, oauth2.AccessTypeOffline)
	if err != nil {
		return nil, err
	}

	idtoken, ok := gResp.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("google auth failed: id_token not found in token response")
	}

	tok, err := jwt.ParseSigned(idtoken)
	if err != nil {
		return nil, err
	}
	cl := struct {
		Email      string `json:"email"`
		IsVerified bool   `json:"email_verified"`
	}{}
	if err := tok.UnsafeClaimsWithoutVerification(&cl); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if !cl.IsVerified {
		return nil, seba.ErrEmailNotVerified.WithMessage("Email address must be verified before using Google")
	}

	user, err := a.Storage.GetUserByEmail(ctx, cl.Email)
	if err != nil {
		return nil, err
	}

	return a.CreateUserCredentials(ctx, user, client, nil)
}
