package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/g-wilson/seba"
)

type Mock struct{}

func (s *Mock) CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (seba.Authentication, error) {
	return seba.Authentication{}, nil
}

func (s *Mock) GetAuthenticationByID(ctx context.Context, authenticationID string) (seba.Authentication, error) {
	return seba.Authentication{}, nil
}

func (s *Mock) GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (seba.Authentication, error) {
	pkceValue := "ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=" // base64 encoded string of the sha256 hash of "a"

	switch hashedCode {
	case sha256Hex("code-exists"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: pkceValue,
		}, nil
	case sha256Hex("code-exists-newuser"):
		return seba.Authentication{
			ID:            "b",
			Email:         "test-b@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: pkceValue,
		}, nil
	case sha256Hex("client-id-mismatch"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "2q3f3ev13fg1",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: pkceValue,
		}, nil
	case sha256Hex("expired"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (48 * time.Hour)),
			PKCEChallenge: pkceValue,
		}, nil
	case sha256Hex("verified"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: pkceValue,
			VerifiedAt:    ptrTime(time.Now().UTC().Add(0 - (10 * time.Second))),
		}, nil
	case sha256Hex("revoked"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: pkceValue,
			RevokedAt:     ptrTime(time.Now().UTC().Add(0 - (10 * time.Second))),
		}, nil
	case sha256Hex("pkce-mismatch"):
		return seba.Authentication{
			ID:            "a",
			Email:         "test@example.com",
			ClientID:      "client_a",
			CreatedAt:     time.Now().UTC().Add(0 - (30 * time.Second)),
			PKCEChallenge: "ypeBEaaaaaaaaaaaaaaaaaaa7/gUfE5yuYB3ha/uSLs=",
		}, nil
	default:
		return seba.Authentication{}, seba.ErrAuthnNotFound
	}
}

func (s *Mock) SetAuthenticationVerified(ctx context.Context, authenticationID, email string) error {
	return nil
}

func (s *Mock) RevokePendingAuthentications(ctx context.Context, email string) error {
	return nil
}

func (s *Mock) CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken, grantID string) (seba.RefreshToken, error) {
	return seba.RefreshToken{}, nil
}

func (s *Mock) GetRefreshTokenByID(ctx context.Context, reftokID string) (seba.RefreshToken, error) {
	return seba.RefreshToken{}, nil
}

func (s *Mock) GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (seba.RefreshToken, error) {
	return seba.RefreshToken{}, nil
}

func (s *Mock) SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) error {
	return nil
}

func (s *Mock) GetUserByID(ctx context.Context, userID string) (seba.User, error) {
	switch userID {
	case "user_a":
		return seba.User{
			ID:        "user_a",
			CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
		}, nil
	case "user_b":
		return seba.User{
			ID:        "user_b",
			CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
		}, nil
	default:
		return seba.User{}, seba.ErrUserNotFound
	}
}

func (s *Mock) GetUserByEmail(ctx context.Context, email string) (seba.User, error) {
	switch email {
	case "test@example.com":
		return seba.User{
			ID:        "user_a",
			CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
		}, nil
	default:
		return seba.User{}, seba.ErrUserNotFound
	}
}

func (s *Mock) GetUserExtended(ctx context.Context, userID string) (seba.UserExtended, error) {
	switch userID {
	case "user_a":
		return seba.UserExtended{
			ID:        "user_a",
			CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
			Emails: []seba.Email{
				{
					ID:        "email_a",
					Email:     "test@example.com",
					CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
				},
			},
			SecondFactorEnrolled: false,
		}, nil
	case "user_b":
		return seba.UserExtended{
			ID:        "user_b",
			CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
			Emails: []seba.Email{
				{
					ID:        "email_b",
					Email:     "test-b@example.com",
					CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
				},
			},
			SecondFactorEnrolled: false,
		}, nil
	default:
		return seba.UserExtended{}, seba.ErrUserNotFound
	}
}

func (s *Mock) ListUserEmails(ctx context.Context, userID string) ([]seba.Email, error) {
	switch userID {
	case "user_a":
		return []seba.Email{
			{
				ID:        "email_a",
				Email:     "test@example.com",
				CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
			},
		}, nil
	case "user_b":
		return []seba.Email{
			{
				ID:        "email_b",
				Email:     "test-b@example.com",
				CreatedAt: time.Now().UTC().Add(0 - (48 * time.Hour)),
			},
		}, nil
	default:
		return []seba.Email{}, seba.ErrUserNotFound
	}
}

func (s *Mock) CreateUserWithEmail(ctx context.Context, emailAddress string) (seba.User, error) {
	switch emailAddress {
	case "test@example.com":
		return seba.User{}, seba.ErrEmailTaken
	default:
		return seba.User{
			ID:        "user_b",
			CreatedAt: time.Now().UTC(),
		}, nil
	}
}

func (s *Mock) CreateWebauthnRegistrationChallenge(ctx context.Context, userID, sessionID, challenge string) (seba.WebauthnChallenge, error) {
	return seba.WebauthnChallenge{}, nil
}

func (s *Mock) CreateWebauthnVerificationChallenge(ctx context.Context, userID, sessionID, challenge string, credentialIDs []string) (seba.WebauthnChallenge, error) {
	return seba.WebauthnChallenge{}, nil
}

func (s *Mock) GetWebauthnChallenge(ctx context.Context, challengeID string) (seba.WebauthnChallenge, error) {
	return seba.WebauthnChallenge{}, nil
}

func (s *Mock) ListUserWebauthnCredentials(ctx context.Context, userID string) ([]seba.WebauthnCredential, error) {
	return []seba.WebauthnCredential{}, nil
}

func (s *Mock) GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (seba.WebauthnCredential, error) {
	return seba.WebauthnCredential{}, nil
}

func (s *Mock) CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType, credentialID, publicKey, AAGUID string, userVerified bool, signCount int) (seba.WebauthnCredential, error) {
	return seba.WebauthnCredential{}, nil
}

func (s *Mock) UpdateWebauthnCredential(ctx context.Context, userID, credentialID string, signCount int) error {
	return nil
}

func (s *Mock) CreateGoogleVerification(ctx context.Context, nonce, iss, aud, sub string) (seba.GoogleVerification, error) {
	return seba.GoogleVerification{}, nil
}

func sha256Hex(in string) string {
	digest := sha256.Sum256([]byte(in))
	return hex.EncodeToString(digest[:])
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
