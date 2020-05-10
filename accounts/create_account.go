package accounts

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
)

func (a *App) CreateAccount(ctx context.Context) (*seba.CreateAccountResponse, error) {
	bearer := idcontext.GetIdentity(ctx)
	if !bearer.HasScope(seba.ScopeSebaAdmin) {
		return nil, seba.ErrAccessDenied
	}

	account, err := a.Storage.CreateAccount(ctx)
	if err != nil {
		return nil, err
	}

	return &seba.CreateAccountResponse{AccountID: account.ID}, nil
}
