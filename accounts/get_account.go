package accounts

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
)

func (a *App) GetAccount(ctx context.Context, req *seba.GetAccountRequest) (*seba.GetAccountResponse, error) {
	bearer := idcontext.GetIdentity(ctx)
	if bearer.AccountID != req.AccountID && !bearer.HasScope(seba.ScopeSebaAdmin) {
		return nil, seba.ErrAccessDenied
	}

	account, err := a.Storage.GetAccountByID(ctx, req.AccountID)
	if err != nil {
		return nil, err
	}

	res := &seba.GetAccountResponse{
		ID:        account.ID,
		CreatedAt: account.CreatedAt,
		Users:     []seba.AccountUser{},
	}

	users, err := a.Storage.ListUsersByAccountID(ctx, req.AccountID)
	if err != nil {
		return nil, err
	}

	for _, u := range users {
		res.Users = append(res.Users, seba.AccountUser{
			ID:        u.ID,
			CreatedAt: u.CreatedAt,
		})
	}

	return res, nil
}
