package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"

	"github.com/g-wilson/runtime/hand"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Handler struct {
	Token        token.Token
	Storage      storage.Storage
	Credentials  credentials.CredentialProvider
	Clients      map[string]seba.Client
	GoogleParams GoogleOauthConfig
}

type GoogleOauthConfig struct {
	ClientID     string
	ClientSecret string
}

type Request struct {
	GrantType    string  `json:"grant_type"`
	Code         string  `json:"code"`
	ClientID     string  `json:"client_id"`
	PKCEVerifier *string `json:"pkce_verifier,omitempty"`
}

type Response struct {
	*seba.Credentials
}

func (h *Handler) Do(ctx context.Context, req *Request) (res *Response, err error) {
	client, ok := h.Clients[req.ClientID]
	if !ok {
		return nil, seba.ErrClientNotFound
	}

	var creds *seba.Credentials

	switch req.GrantType {
	case seba.GrantTypeEmailToken:
		creds, err = h.useEmailToken(ctx, req.Code, client, req.PKCEVerifier)
	case seba.GrantTypeRefreshToken:
		creds, err = h.useRefreshToken(ctx, req.Code, client)
	case seba.GrantTypeGoogle:
		creds, err = h.useGoogleToken(ctx, req.Code, client)
	default:
		err = seba.ErrUnsupportedGrantType // should not happen
	}
	if err != nil {
		return nil, err
	}

	return &Response{Credentials: creds}, nil
}

func (h *Handler) useEmailToken(ctx context.Context, token string, client seba.Client, verifier *string) (creds *seba.Credentials, err error) {
	if !client.EnableEmailGrant {
		return nil, seba.ErrNotSupportedByClient
	}

	if verifier == nil {
		return nil, seba.ErrPKCEVerifierRequired
	}

	authn, err := h.Storage.GetAuthenticationByHashedCode(ctx, sha256Hex(token))
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

	user, err := h.getOrCreateUserByEmail(ctx, authn.Email)
	if err != nil {
		return nil, err
	}

	creds, err = h.Credentials.CreateForUser(ctx, user, client, &authn.ID)
	if err != nil {
		return nil, err
	}

	err = h.Storage.SetAuthenticationVerified(ctx, authn.ID, authn.Email)
	if err != nil {
		return nil, err
	}

	err = h.Storage.RevokePendingAuthentications(ctx, authn.Email)
	if err != nil {
		return nil, err
	}

	return
}

func (h *Handler) useRefreshToken(ctx context.Context, token string, client seba.Client) (*seba.Credentials, error) {
	if !client.EnableRefreshTokenGrant {
		return nil, seba.ErrNotSupportedByClient
	}

	rt, err := h.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(token))
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

	user, err := h.Storage.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	creds, err := h.Credentials.CreateForUser(ctx, user, client, rt.AuthenticationID)
	if err != nil {
		return nil, err
	}

	err = h.Storage.SetRefreshTokenUsed(ctx, rt.ID, user.ID)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func (h *Handler) useGoogleToken(ctx context.Context, code string, client seba.Client) (*seba.Credentials, error) {
	if !client.EnableEmailGrant {
		return nil, seba.ErrNotSupportedByClient
	}

	googleConfig := &oauth2.Config{
		ClientID:     h.GoogleParams.ClientID,
		ClientSecret: h.GoogleParams.ClientSecret,
		RedirectURL:  client.CallbackURL,
	}

	gResp, err := googleConfig.Exchange(ctx, code, oauth2.AccessTypeOffline)
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

	user, err := h.getOrCreateUserByEmail(ctx, cl.Email)
	if err != nil {
		return nil, err
	}

	return h.Credentials.CreateForUser(ctx, user, client, nil)
}

func (h *Handler) getOrCreateUserByEmail(ctx context.Context, email string) (seba.User, error) {
	createUser := false

	user, err := h.Storage.GetUserByEmail(ctx, email)
	if err != nil {
		if hand.Matches(err, seba.ErrUserNotFound) {
			createUser = true
		} else {
			return seba.User{}, err
		}
	}

	if createUser {
		newUser, err := h.Storage.CreateUserWithEmail(ctx, email)
		if err != nil {
			return seba.User{}, err
		}

		user = newUser
	}

	return user, nil
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
