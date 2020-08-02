package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/runtime/logger"
	"github.com/sirupsen/logrus"

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

func convertFromStoredCredential(cred *storage.WebauthnCredential) (ret webauthn.Credential, err error) {
	credIDBytes, err := base64.StdEncoding.DecodeString(cred.CredentialID)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cred.PublicKey)
	aaguidBytes, err := base64.StdEncoding.DecodeString(cred.AAGUID)
	if err != nil {
		return ret, fmt.Errorf("base64 decode failed for credential %s: %w", cred.ID, err)
	}

	return webauthn.Credential{
		ID:              credIDBytes,
		PublicKey:       pubKeyBytes,
		AttestationType: cred.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguidBytes,
			SignCount: uint32(cred.SignCount),
		},
	}, nil
}

func convertFromStoredChallenge(chal *storage.WebauthnChallenge, userID string) (ret webauthn.SessionData, err error) {
	var allowedCredsBytes = make([][]byte, len(chal.CredentialIDs))
	for i, c := range chal.CredentialIDs {
		cBytes, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return ret, err
		}

		allowedCredsBytes[i] = cBytes
	}

	return webauthn.SessionData{
		Challenge:            chal.Challenge,
		UserID:               []byte(userID),
		AllowedCredentialIDs: allowedCredsBytes,
		UserVerification:     protocol.VerificationDiscouraged, // hard-coded for now
	}, nil
}

func (a *App) getWebauthnContext(ctx context.Context, rt *storage.RefreshToken) (*webauthnUserContext, *webauthn.WebAuthn, error) {
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

	storedCreds, err := a.Storage.ListUserWebauthnCredentials(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	var creds = make([]webauthn.Credential, len(storedCreds))
	for i, c := range storedCreds {
		parsedCred, err := convertFromStoredCredential(c)
		if err != nil {
			return nil, nil, err
		}

		creds[i] = parsedCred
	}

	// TODO: parallelise a lot of the above

	wanUser := &webauthnUserContext{
		Client:       &client,
		RefreshToken: rt,
		User:         user,
		Emails:       emails,
		Creds:        creds,
	}

	return wanUser, wanContext, nil
}

func (a *App) StartWebauthnRegistration(ctx context.Context, req *seba.StartWebauthnRegistrationRequest) (*seba.StartWebauthnRegistrationResponse, error) {
	rt, err := a.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(req.RefreshToken))
	if err != nil {
		return nil, err
	}

	userContext, wanContext, err := a.getWebauthnContext(ctx, rt)
	if err != nil {
		return nil, err
	}

	pubKeyOpts, sessionData, err := wanContext.BeginRegistration(userContext, func(opts *protocol.PublicKeyCredentialCreationOptions) {
		opts.AuthenticatorSelection = protocol.AuthenticatorSelection{
			RequireResidentKey: ptrBool(false),
			UserVerification:   protocol.VerificationDiscouraged,
			// AuthenticatorAttachment: protocol.CrossPlatform, // protocol.Platform
		}
		// opts.Attestation = protocol.PreferDirectAttestation
		opts.Attestation = protocol.PreferNoAttestation
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	chal, err := a.Storage.CreateWebauthnRegistrationChallenge(ctx, userContext.RefreshToken.ID, sessionData.Challenge)
	if err != nil {
		return nil, err
	}

	return &seba.StartWebauthnRegistrationResponse{
		ChallengeID:        chal.ID,
		AttestationOptions: pubKeyOpts.Response,
	}, nil
}

func (a *App) CompleteWebauthnRegistration(ctx context.Context, req *seba.CompleteWebauthnRegistrationRequest) (*seba.CompleteWebauthnRegistrationResponse, error) {
	storedSession, err := a.Storage.GetWebauthnChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, err
	}
	if storedSession.CreatedAt.Add(1 * time.Minute).Before(time.Now()) {
		return nil, hand.New("webauthn_session_expired")
	}

	rt, err := a.Storage.GetRefreshTokenByID(ctx, storedSession.SessionID)
	if err != nil {
		return nil, err
	}

	userContext, wanContext, err := a.getWebauthnContext(ctx, rt)
	if err != nil {
		return nil, err
	}

	attResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.AttestationResponse))
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(attResponse)
	if err != nil {
		return nil, err
	}

	sessionData := webauthn.SessionData{
		Challenge: storedSession.Challenge,
		UserID:    []byte(userContext.User.ID),
	}
	cred, err := wanContext.CreateCredential(userContext, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	credIDString := base64.StdEncoding.EncodeToString(cred.ID)

	logger.FromContext(ctx).Entry().WithFields(logrus.Fields{
		"credential_id": credIDString,
		"aaguid":        base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID),
	}).Info("adding credential")

	_, err = a.Storage.GetWebauthnCredentialByCredentialID(ctx, credIDString)
	if err == nil {
		return nil, hand.New("webauthn_credential_already_registered")
	}
	if !hand.Matches(err, seba.ErrWebauthnCredentialNotFound) {
		return nil, err
	}

	pubKeyString := base64.StdEncoding.EncodeToString(cred.PublicKey)
	aaguidString := base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID)
	_, err = a.Storage.CreateWebAuthnCredential(ctx, userContext.User.ID, "", cred.AttestationType, credIDString, pubKeyString, aaguidString, int(cred.Authenticator.SignCount))
	if err != nil {
		return nil, err
	}

	isUserVerified := parsedResponse.Response.AttestationObject.AuthData.Flags.UserVerified()
	tokens, err := a.CreateElevatedUserCredentials(ctx, userContext.User, *userContext.Client, userContext.RefreshToken.AuthenticationID, isUserVerified)
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
	rt, err := a.Storage.GetRefreshTokenByHashedToken(ctx, sha256Hex(req.RefreshToken))
	if err != nil {
		return nil, err
	}

	userContext, wanContext, err := a.getWebauthnContext(ctx, rt)
	if err != nil {
		return nil, err
	}

	assertionOpts, sessionData, err := wanContext.BeginLogin(userContext, func(opts *protocol.PublicKeyCredentialRequestOptions) {
		opts.UserVerification = protocol.VerificationDiscouraged
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	var stringCreds = make([]string, len(sessionData.AllowedCredentialIDs))
	for i, c := range sessionData.AllowedCredentialIDs {
		stringCreds[i] = base64.StdEncoding.EncodeToString(c)
	}

	chal, err := a.Storage.CreateWebauthnVerificationChallenge(ctx, userContext.RefreshToken.ID, sessionData.Challenge, stringCreds)
	if err != nil {
		return nil, err
	}

	return &seba.StartWebauthnVerificationResponse{
		ChallengeID:      chal.ID,
		AssertionOptions: assertionOpts.Response,
	}, nil
}

func (a *App) CompleteWebauthnVerification(ctx context.Context, req *seba.CompleteWebauthnVerificationRequest) (*seba.CompleteWebauthnVerificationResponse, error) {
	storedSession, err := a.Storage.GetWebauthnChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, err
	}
	if storedSession.CreatedAt.Add(1 * time.Minute).Before(time.Now()) {
		return nil, hand.New("webauthn_session_expired")
	}

	rt, err := a.Storage.GetRefreshTokenByID(ctx, storedSession.SessionID)
	if err != nil {
		return nil, err
	}

	userContext, wanContext, err := a.getWebauthnContext(ctx, rt)
	if err != nil {
		return nil, err
	}

	assertionResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.AssertionResponse))
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(assertionResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	sessionData, err := convertFromStoredChallenge(storedSession, userContext.User.ID)
	if err != nil {
		return nil, err
	}

	credential, err := wanContext.ValidateLogin(userContext, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	if credential.Authenticator.CloneWarning {
		return nil, hand.New("clone_warning")
	}

	credIDString := base64.StdEncoding.EncodeToString(credential.ID)
	err = a.Storage.UpdateWebauthnCredential(ctx, userContext.User.ID, credIDString, int(credential.Authenticator.SignCount))
	if err != nil {
		return nil, err
	}

	isUserVerified := parsedResponse.Response.AuthenticatorData.Flags.UserVerified()
	tokens, err := a.CreateElevatedUserCredentials(ctx, userContext.User, *userContext.Client, userContext.RefreshToken.AuthenticationID, isUserVerified)
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
