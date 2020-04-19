package app

import (
	"context"
	"fmt"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/emails"
	"github.com/g-wilson/seba/idcontext"

	"github.com/g-wilson/runtime/logger"
)

func (a *App) SendInviteEmail(ctx context.Context, req *seba.SendInviteEmailRequest) (*seba.SendInviteEmailResponse, error) {
	bearer := idcontext.GetIdentity(ctx)
	if bearer.AccountID != req.AccountID && !bearer.HasScope(seba.ScopeSebaAdmin) {
		return nil, seba.ErrAccessDenied
	}

	invTok, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}

	invite, err := a.Storage.CreateInvite(ctx, req.AccountID, req.Email, invTok)
	if err != nil {
		return nil, err
	}

	a.Logger.Debugf("invite_token: %s", invTok)

	linkURL := fmt.Sprintf("%s?invite_token=%s", InviteCallbackURL, invTok)
	email, err := emails.NewInviteEmail(req.Email, linkURL)
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
