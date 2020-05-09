package app

import (
	"context"
	"fmt"
	"net/url"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/emails"

	"github.com/g-wilson/runtime/logger"
)

func (a *App) SendAuthenticationEmail(ctx context.Context, req *seba.SendAuthenticationEmailRequest) error {
	client, ok := clientsByID[req.ClientID]
	if !ok {
		return seba.ErrClientNotFound
	}

	// TODO: revoke all unverified authentications for the same email

	emailToken, err := GenerateToken(32)
	if err != nil {
		return err
	}

	_, err = a.Storage.CreateAuthentication(ctx, sha256Hex(emailToken), req.Email, req.PKCEChallenge, req.ClientID)
	if err != nil {
		return err
	}

	a.Logger.Debugf("email_token: %s", emailToken)

	linkURL := fmt.Sprintf("%s?code=%s&state=%s", client.EmailAuthenticationURL, emailToken, url.QueryEscape(req.State))

	a.Logger.Debugf("link_url: %s", linkURL)

	email, err := emails.NewAuthenticationEmail(req.Email, linkURL)
	if err != nil {
		logger.FromContext(ctx).Entry().
			WithError(err).
			WithField("email_template", "authentication").
			Error("invite email template failed")

		return seba.ErrCreatingEmail
	}

	if a.actuallySendEmails {
		_, err = a.ses.SendEmailWithContext(ctx, email)
		if err != nil {
			logger.FromContext(ctx).Entry().Errorf("authn email sending failed: %v", err)

			return seba.ErrSendingEmail
		}
	}

	return nil
}
