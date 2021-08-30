package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/g-wilson/seba"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/g-wilson/runtime/hand"
	"golang.org/x/sync/errgroup"
)

// UserContext provides user data for the webauthn handlers and meets the webauthn library interface
type UserContext struct {
	User   seba.User
	Emails []seba.Email
	Creds  []webauthn.Credential
}

func (u *UserContext) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

func (u *UserContext) WebAuthnName() string {
	return u.Emails[0].Email
}

func (u *UserContext) WebAuthnDisplayName() string {
	return u.Emails[0].Email
}

func (u *UserContext) WebAuthnIcon() string {
	return ""
}

func (u *UserContext) WebAuthnCredentials() []webauthn.Credential {
	return u.Creds
}

func (a *Webauthn) getUserContext(ctx context.Context, userID string) (*UserContext, error) {
	var user seba.User
	var emails []seba.Email
	creds := []webauthn.Credential{}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() (err error) {
		user, err = a.Storage.GetUserByID(gctx, userID)

		return
	})

	g.Go(func() (err error) {
		emails, err = a.Storage.ListUserEmails(gctx, userID)
		if err != nil {
			return
		}

		if len(emails) < 1 {
			err = hand.
				New("email_registration_required").
				WithMessage("You must have a registered email address before using webauthn")
		}

		return
	})

	g.Go(func() (err error) {
		storedCreds, err := a.Storage.ListUserWebauthnCredentials(gctx, userID)
		if err != nil {
			return err
		}

		for _, c := range storedCreds {
			parsedCred, err := convertFromStoredCredential(c)
			if err != nil {
				return err
			}

			creds = append(creds, parsedCred)
		}

		return
	})

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	return &UserContext{
		User:   user,
		Emails: emails,
		Creds:  creds,
	}, nil
}

func convertFromStoredCredential(cred seba.WebauthnCredential) (ret webauthn.Credential, err error) {
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

func convertFromStoredChallenge(chal seba.WebauthnChallenge, userID string) (ret webauthn.SessionData, err error) {
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
