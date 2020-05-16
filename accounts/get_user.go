package accounts

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
)

func (a *App) GetUser(ctx context.Context, req *seba.GetUserRequest) (*seba.GetUserResponse, error) {
	bearer := idcontext.GetIdentity(ctx)
	if bearer.UserID != req.UserID && !bearer.HasScope(seba.ScopeSebaAdmin) {
		return nil, seba.ErrAccessDenied
	}

	user, err := a.Storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	ems, err := a.Storage.ListUserEmails(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	res := &seba.GetUserResponse{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		AccountID: user.AccountID,
		Emails:    []seba.UserEmail{},
	}

	for _, em := range ems {
		res.Emails = append(res.Emails, seba.UserEmail{CreatedAt: em.CreatedAt, Value: em.Email})
	}

	return res, nil
}
