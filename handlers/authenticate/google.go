package authenticate

import (
	"context"

	"github.com/g-wilson/seba"

	"github.com/g-wilson/runtime/logger"
)

func (h *Handler) useGoogleToken(ctx context.Context, code string, client seba.Client) (string, string, error) {
	if !client.EnableGoogleGrant {
		return "", "", seba.ErrNotSupportedByClient
	}

	cl, err := h.GoogleVerifier.Verify(ctx, code)
	if err != nil {
		logger.FromContext(ctx).Update(
			logger.FromContext(ctx).Entry().WithField("google_verifier_error", err),
		)

		return "", "", seba.ErrGoogleVerifyFailed.WithMessage("Google ID token invalid")
	}

	if cl.Nonce == "" {
		return "", "", seba.ErrGoogleVerifyFailed.WithMessage("Nonce must be available")
	}

	if cl.Email == "" {
		return "", "", seba.ErrGoogleVerifyFailed.WithMessage("Email address must be available")
	}

	if !cl.EmailVerified {
		return "", "", seba.ErrGoogleVerifyFailed.WithMessage("Email address must be verified")
	}

	// checks if nonce has already been used, errors with seba.ErrGoogleAlreadyVerified
	gv, err := h.Storage.CreateGoogleVerification(ctx, cl.Nonce, cl.Issuer, cl.Audience[0], cl.Subject)
	if err != nil {
		return "", "", err
	}

	user, err := h.getOrCreateUserByEmail(ctx, cl.Email)
	if err != nil {
		return "", "", err
	}

	return user.ID, gv.ID, nil
}
