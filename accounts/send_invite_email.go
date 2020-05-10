package accounts

import (
	"bytes"
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
	"github.com/g-wilson/seba/token"

	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/runtime/logger"
)

type inviteEmailTemplateData struct {
	InviteToken string
}

func (a *App) SendInviteEmail(ctx context.Context, req *seba.SendInviteEmailRequest) (*seba.SendInviteEmailResponse, error) {
	bearer := idcontext.GetIdentity(ctx)
	if bearer.AccountID != req.AccountID && !bearer.HasScope(seba.ScopeSebaAdmin) {
		return nil, seba.ErrAccessDenied
	}

	invTok, err := token.GenerateToken(32)
	if err != nil {
		return nil, err
	}

	invite, err := a.Storage.CreateInvite(ctx, req.AccountID, req.Email, invTok)
	if err != nil {
		return nil, err
	}

	a.Logger.Debugf("invite_token: %s", invTok)

	email, err := a.createInviteEmail(req.Email, invTok)
	if err != nil {
		logger.FromContext(ctx).Entry().
			WithError(err).
			WithField("email_template", "invite").
			Error("invite email template failed")

		return nil, seba.ErrCreatingEmail
	}

	if a.actuallySendEmails {
		_, err = a.ses.SendEmailWithContext(ctx, email)
		if err != nil {
			logger.FromContext(ctx).Entry().
				WithError(err).
				Error("invite email sending failed")

			return nil, seba.ErrSendingEmail
		}
	}

	return &seba.SendInviteEmailResponse{InviteID: invite.ID}, nil
}

func (a *App) createInviteEmail(toAddress, token string) (*ses.SendEmailInput, error) {
	var output bytes.Buffer
	err := a.emailConfig.InviteEmailTemplate.Execute(&output, inviteEmailTemplateData{token})
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
				Data:    &a.emailConfig.InviteEmailSubject,
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
