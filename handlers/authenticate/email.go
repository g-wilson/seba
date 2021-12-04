package authenticate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/g-wilson/seba"
)

func (f *Function) useEmailToken(ctx context.Context, token string, client seba.Client, verifier *string) (string, string, error) {
	if !client.EnableEmailGrant {
		return "", "", seba.ErrNotSupportedByClient
	}

	if verifier == nil {
		return "", "", seba.ErrPKCEVerifierRequired
	}

	authn, err := f.Storage.GetAuthenticationByHashedCode(ctx, sha256Hex(token))
	if err != nil {
		return "", "", err
	}
	if authn.ClientID != client.ID {
		return "", "", seba.ErrClientIDMismatch
	}
	if authn.CreatedAt.Add(5 * time.Minute).Before(time.Now()) {
		return "", "", seba.ErrAuthnExpired
	}
	if authn.VerifiedAt != nil {
		return "", "", seba.ErrAuthnAlreadyVerified
	}
	if authn.RevokedAt != nil {
		return "", "", seba.ErrAuthnRevoked
	}

	verifierBytes, err := base64.RawURLEncoding.DecodeString(*verifier)
	if err != nil {
		return "", "", err
	}

	hashedVerifier := sha256.Sum256(verifierBytes)
	b64HashedVerifier := base64.RawURLEncoding.EncodeToString(hashedVerifier[:])

	if subtle.ConstantTimeCompare([]byte(b64HashedVerifier), []byte(authn.PKCEChallenge)) != 1 {
		return "", "", seba.ErrPKCEChallengeFailed
	}

	user, err := f.getOrCreateUserByEmail(ctx, authn.Email)
	if err != nil {
		return "", "", err
	}

	err = f.Storage.SetAuthenticationVerified(ctx, authn.ID, authn.Email)
	if err != nil {
		return "", "", err
	}

	err = f.Storage.RevokePendingAuthentications(ctx, authn.Email)
	if err != nil {
		return "", "", err
	}

	return user.ID, authn.ID, nil
}
