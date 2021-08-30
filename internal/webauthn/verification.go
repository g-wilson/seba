package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/g-wilson/runtime/hand"
	"github.com/g-wilson/seba"
)

func (a *Webauthn) StartVerification(ctx context.Context, userID, sessionID string) (StartVerificationResponse, error) {
	userContext, err := a.getUserContext(ctx, userID)
	if err != nil {
		return StartVerificationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	assertionOpts, sessionData, err := a.Provider.BeginLogin(userContext, credentialRequestOptions)
	if err != nil {
		return StartVerificationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	var stringCreds = make([]string, len(sessionData.AllowedCredentialIDs))
	for i, c := range sessionData.AllowedCredentialIDs {
		stringCreds[i] = base64.StdEncoding.EncodeToString(c)
	}

	chal, err := a.Storage.CreateWebauthnVerificationChallenge(ctx, userID, sessionID, sessionData.Challenge, stringCreds)
	if err != nil {
		return StartVerificationResponse{}, fmt.Errorf("webauthn: %w", err)
	}

	return StartVerificationResponse{
		Challenge:        chal,
		AssertionOptions: assertionOpts.Response,
	}, nil
}

func (a *Webauthn) CompleteVerification(ctx context.Context, challenge seba.WebauthnChallenge, assertionResponse string) (err error) {
	if challenge.CreatedAt.Add(RegistrationTTL).Before(time.Now()) {
		return hand.New("webauthn_session_expired")
	}

	userContext, err := a.getUserContext(ctx, challenge.UserID)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}

	decodedAssertionResponse := base64.NewDecoder(base64.StdEncoding, strings.NewReader(assertionResponse))
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(decodedAssertionResponse)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}

	sessionData, err := convertFromStoredChallenge(challenge, userContext.User.ID)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}

	credential, err := a.Provider.ValidateLogin(userContext, sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}
	if credential.Authenticator.CloneWarning {
		return hand.New("clone_warning")
	}

	credIDString := base64.StdEncoding.EncodeToString(credential.ID)
	err = a.Storage.UpdateWebauthnCredential(ctx, userContext.User.ID, credIDString, int(credential.Authenticator.SignCount))
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}

	return
}
