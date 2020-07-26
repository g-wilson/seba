package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/g-wilson/runtime/hand"
)

// TODO: remove this
var tmpRegisterSessionData webauthn.SessionData
var tmpVerifySessionData webauthn.SessionData
var tmpCredentials = []webauthn.Credential{}

// webauthnUserContext provides user data for the webauthn handlers and meets the webauthn library interface
type webauthnUserContext struct {
	Client       *seba.Client
	RefreshToken *storage.RefreshToken
	User         *storage.User
	Emails       []*storage.Email
	Creds        []webauthn.Credential
}

func (u *webauthnUserContext) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

func (u *webauthnUserContext) WebAuthnName() string {
	return u.Emails[0].Email
}

func (u *webauthnUserContext) WebAuthnDisplayName() string {
	return u.Emails[0].Email
}

func (u *webauthnUserContext) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUserContext) WebAuthnCredentials() []webauthn.Credential {
	return u.Creds
}

func (a *App) getWebauthnContext(ctx context.Context, refreshToken string) (*webauthnUserContext, *webauthn.WebAuthn, error) {
	rt, err := a.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(refreshToken))
	if err != nil {
		return nil, nil, err
	}
	if rt.UsedAt != nil {
		return nil, nil, seba.ErrRefreshTokenUsed
	}

	client, ok := a.clientsByID[rt.ClientID]
	if !ok {
		return nil, nil, seba.ErrClientNotFound
	}
	if !client.WebauthnEnabled() {
		return nil, nil, seba.ErrNotSupportedByClient
	}

	wanContext, err := webauthn.New(&webauthn.Config{
		RPDisplayName: a.webauthnConfig.RPDisplayName,
		RPID:          a.webauthnConfig.RPID,
		RPOrigin:      client.WebauthnOrigin,
		Debug:         true,
	})
	if err != nil {
		return nil, nil, err
	}

	user, err := a.Storage.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, nil, err
	}

	emails, err := a.Storage.ListUserEmails(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(emails) < 1 {
		return nil, nil, hand.
			New("email_registration_required").
			WithMessage("You must have a registered email address before using webauthn")
	}

	// TODO: get webauthn credentials from storage
	wanCreds := tmpCredentials

	// TODO: parallelise a lot of the above

	wanUser := &webauthnUserContext{
		Client:       &client,
		RefreshToken: rt,
		User:         user,
		Emails:       emails,
		Creds:        wanCreds,
	}

	return wanUser, wanContext, nil
}

func (a *App) StartWebauthnRegistration(ctx context.Context, req *seba.StartWebauthnRegistrationRequest) (*seba.StartWebauthnRegistrationResponse, error) {
	user, wanContext, err := a.getWebauthnContext(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	pubKeyOpts, sessionData, err := wanContext.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	pubKeyOpts.Response.AuthenticatorSelection = protocol.AuthenticatorSelection{
		RequireResidentKey: ptrBool(false),
		UserVerification:   protocol.VerificationDiscouraged,
	}

	pubKeyOpts.Response.Attestation = protocol.PreferNoAttestation

	// TODO: store session data somewhere
	tmpRegisterSessionData = *sessionData

	return &seba.StartWebauthnRegistrationResponse{
		AssertionOptions: pubKeyOpts.Response,
	}, nil
}

func (a *App) CompleteWebauthnRegistration(ctx context.Context, req *seba.CompleteWebauthnRegistrationRequest) (*seba.CompleteWebauthnRegistrationResponse, error) {
	userContext, wanContext, err := a.getWebauthnContext(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	assertionResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.AssertionResponse))
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(assertionResponse)
	if err != nil {
		return nil, err
	}

	// TODO: load the session data
	sessionData := tmpRegisterSessionData

	credential, err := wanContext.CreateCredential(userContext, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	if credential.AttestationType != string(protocol.PreferNoAttestation) {
		return nil, hand.New("attestation_type_mismatch")
	}

	// TODO: check that the credential.ID is not yet registered to any other user

	// TODO: save the credential against the user
	tmpCredentials = append(tmpCredentials, *credential)

	// TODO: generate new credentials in elevated state
	tokens, err := a.CreateUserCredentials(ctx, userContext.User, *userContext.Client, userContext.RefreshToken.AuthenticationID)
	if err != nil {
		return nil, err
	}

	err = a.Storage.SetRefreshTokenUsed(ctx, userContext.RefreshToken.ID, userContext.User.ID)
	if err != nil {
		return nil, err
	}

	return &seba.CompleteWebauthnRegistrationResponse{
		RefreshToken: tokens.RefreshToken,
		AccessToken:  tokens.AccessToken,
	}, nil
}

func (a *App) StartWebauthnVerification(ctx context.Context, req *seba.StartWebauthnVerificationRequest) (*seba.StartWebauthnVerificationResponse, error) {
	userContext, wanContext, err := a.getWebauthnContext(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	assertionOpts, sessionData, err := wanContext.BeginLogin(userContext)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	// TODO: store session data somewhere
	tmpVerifySessionData = *sessionData

	return &seba.StartWebauthnVerificationResponse{
		AssertionOptions: assertionOpts.Response,
	}, nil
}

func (a *App) CompleteWebauthnVerification(ctx context.Context, req *seba.CompleteWebauthnVerificationRequest) (*seba.CompleteWebauthnVerificationResponse, error) {
	userContext, wanContext, err := a.getWebauthnContext(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	// TODO: load the session data
	sessionData := tmpVerifySessionData

	assertionResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.AssertionResponse))
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(assertionResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	_, err = wanContext.ValidateLogin(userContext, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	// TODO: generate new credentials in elevated state
	tokens, err := a.CreateUserCredentials(ctx, userContext.User, *userContext.Client, userContext.RefreshToken.AuthenticationID)
	if err != nil {
		return nil, err
	}

	err = a.Storage.SetRefreshTokenUsed(ctx, userContext.RefreshToken.ID, userContext.User.ID)
	if err != nil {
		return nil, err
	}

	return &seba.CompleteWebauthnVerificationResponse{
		RefreshToken: tokens.RefreshToken,
		AccessToken:  tokens.AccessToken,
	}, nil
}
