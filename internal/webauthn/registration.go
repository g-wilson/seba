package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/g-wilson/runtime/hand"
)

func (a *Webauthn) StartRegistration(ctx context.Context, userID, sessionID string) (StartRegistrationResponse, error) {
	userContext, err := a.getUserContext(ctx, userID)
	if err != nil {
		return StartRegistrationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	pubKeyOpts, sessionData, err := a.Provider.BeginRegistration(userContext, credentialCreationOptions)
	if err != nil {
		return StartRegistrationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	chal, err := a.Storage.CreateWebauthnRegistrationChallenge(ctx, userID, sessionID, sessionData.Challenge)
	if err != nil {
		return StartRegistrationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	return StartRegistrationResponse{
		Challenge:          chal,
		AttestationOptions: pubKeyOpts.Response,
	}, nil
}

func (a *Webauthn) CompleteRegistration(ctx context.Context, challenge seba.WebauthnChallenge, attestationResponse string) (seba.WebauthnCredential, error) {
	if challenge.CreatedAt.Add(RegistrationTTL).Before(time.Now()) {
		return seba.WebauthnCredential{}, hand.New("webauthn_session_expired")
	}

	userContext, err := a.getUserContext(ctx, challenge.UserID)
	if err != nil {
		return seba.WebauthnCredential{}, fmt.Errorf("webauthn: %w", err)
	}

	attResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(attestationResponse))
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(attResponse)
	if err != nil {
		return seba.WebauthnCredential{}, fmt.Errorf("webauthn: %w", err)
	}

	sessionData := webauthn.SessionData{
		Challenge: challenge.Challenge,
		UserID:    []byte(userContext.User.ID),
	}
	cred, err := a.Provider.CreateCredential(userContext, sessionData, parsedResponse)
	if err != nil {
		return seba.WebauthnCredential{}, fmt.Errorf("webauthn: %w", err)
	}

	credIDString := base64.StdEncoding.EncodeToString(cred.ID)

	_, err = a.Storage.GetWebauthnCredentialByCredentialID(ctx, credIDString)
	if err == nil {
		return seba.WebauthnCredential{}, hand.New("webauthn_credential_already_registered")
	}
	if !hand.Matches(err, seba.ErrWebauthnCredentialNotFound) {
		return seba.WebauthnCredential{}, fmt.Errorf("webauthn: %w", err)
	}

	userVerified := parsedResponse.Response.AttestationObject.AuthData.Flags.UserVerified()
	pubKeyString := base64.StdEncoding.EncodeToString(cred.PublicKey)
	aaguidString := base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID)

	return a.Storage.CreateWebAuthnCredential(
		ctx,
		userContext.User.ID,
		"",
		cred.AttestationType,
		credIDString,
		pubKeyString,
		aaguidString,
		userVerified,
		int(cred.Authenticator.SignCount),
	)
}
