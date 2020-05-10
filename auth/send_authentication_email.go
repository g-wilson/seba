package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/token"

	"github.com/g-wilson/runtime/logger"
)

type authnEmailTemplateData struct {
	LinkURL string
}

func (a *App) SendAuthenticationEmail(ctx context.Context, req *seba.SendAuthenticationEmailRequest) error {
	client, ok := a.clientsByID[req.ClientID]
	if !ok {
		return seba.ErrClientNotFound
	}

	// TODO: revoke all unverified authentications for the same email

	emailToken, err := token.GenerateToken(32)
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

	email, err := a.createAuthenticationEmail(req.Email, linkURL)
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

func (a *App) createAuthenticationEmail(toAddress, linkURL string) (*ses.SendEmailInput, error) {
	var output bytes.Buffer
	err := a.emailConfig.AuthnEmailTemplate.Execute(&output, authnEmailTemplateData{linkURL})
	if err != nil {
		return nil, err
	}

	outputStr := output.String()

	return &ses.SendEmailInput{
		Destination:      &ses.Destination{ToAddresses: []*string{&toAddress}},
		ReplyToAddresses: []*string{&a.emailConfig.DefaultReplyAddress},
		Source:           &a.emailConfig.DefaultFromAddress,
		Message: &ses.Message{
			Subject: &ses.Content{
				Charset: strPointer("UTF-8"),
				Data:    &a.emailConfig.AuthnEmailSubject,
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: strPointer("UTF-8"),
					Data:    &outputStr,
				},
				Text: &ses.Content{
					Charset: strPointer("UTF-8"),
					Data:    &outputStr,
				},
			},
		},
	}, nil
}
