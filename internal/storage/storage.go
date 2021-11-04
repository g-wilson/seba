package storage

import (
	"context"

	"github.com/g-wilson/seba"
)

type Storage interface {
	CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (seba.Authentication, error)
	GetAuthenticationByID(ctx context.Context, authenticationID string) (seba.Authentication, error)
	GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (seba.Authentication, error)
	SetAuthenticationVerified(ctx context.Context, authenticationID, email string) error
	RevokePendingAuthentications(ctx context.Context, email string) error

	CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (seba.RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, reftokID string) (seba.RefreshToken, error)
	GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (seba.RefreshToken, error)
	SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) error

	GetUserByID(ctx context.Context, userID string) (seba.User, error)
	GetUserByEmail(ctx context.Context, email string) (seba.User, error)
	ListUserEmails(ctx context.Context, userID string) ([]seba.Email, error)
	CreateUserWithEmail(ctx context.Context, emailAddress string) (seba.User, error)

	CreateWebauthnRegistrationChallenge(ctx context.Context, userID, sessionID, challenge string) (seba.WebauthnChallenge, error)
	CreateWebauthnVerificationChallenge(ctx context.Context, userID, sessionID, challenge string, credentialIDs []string) (seba.WebauthnChallenge, error)
	GetWebauthnChallenge(ctx context.Context, challengeID string) (seba.WebauthnChallenge, error)

	ListUserWebauthnCredentials(ctx context.Context, userID string) ([]seba.WebauthnCredential, error)
	GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (seba.WebauthnCredential, error)
	CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType, credentialID, publicKey, AAGUID string, userVerified bool, signCount int) (seba.WebauthnCredential, error)
	UpdateWebauthnCredential(ctx context.Context, userID, credentialID string, signCount int) error

	CreateGoogleVerification(ctx context.Context, nonce, iss, aud, sub string) error
}
