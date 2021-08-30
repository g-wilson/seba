package webauthn

import (
	"context"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

var RegistrationTTL = 5 * time.Minute
var VerificationTTL = 5 * time.Minute
var UserVerificationPreference = protocol.VerificationDiscouraged

type WebauthnProvider interface {
	StartRegistration(ctx context.Context, userID, sessionID string) (StartRegistrationResponse, error)
	CompleteRegistration(ctx context.Context, challenge seba.WebauthnChallenge, attestationResponse string) (seba.WebauthnCredential, error)
	StartVerification(ctx context.Context, userID, sessionID string) (StartVerificationResponse, error)
	CompleteVerification(ctx context.Context, challenge seba.WebauthnChallenge, assertionResponse string) error
}

type Webauthn struct {
	Provider *webauthn.WebAuthn
	Storage  storage.Storage
}

type Params struct {
	RPDisplayName string
	RPID          string
	RPOrigin      string
	Storage       storage.Storage
}

type StartRegistrationResponse struct {
	Challenge          seba.WebauthnChallenge
	AttestationOptions protocol.PublicKeyCredentialCreationOptions
}

type StartVerificationResponse struct {
	Challenge        seba.WebauthnChallenge
	AssertionOptions protocol.PublicKeyCredentialRequestOptions
}

func New(cfg Params) (*Webauthn, error) {
	wanProvider, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigin:      cfg.RPOrigin,
	})
	if err != nil {
		return nil, err
	}

	return &Webauthn{
		Provider: wanProvider,
	}, nil
}

func credentialCreationOptions(opts *protocol.PublicKeyCredentialCreationOptions) {
	opts.AuthenticatorSelection = protocol.AuthenticatorSelection{
		RequireResidentKey:      ptrBool(false),
		UserVerification:        UserVerificationPreference,
		AuthenticatorAttachment: protocol.CrossPlatform, // protocol.Platform
	}
	// opts.Attestation = protocol.PreferDirectAttestation
	opts.Attestation = protocol.PreferNoAttestation
}

func credentialRequestOptions(opts *protocol.PublicKeyCredentialRequestOptions) {
	opts.UserVerification = UserVerificationPreference
}

func ptrBool(b bool) *bool {
	return &b
}
