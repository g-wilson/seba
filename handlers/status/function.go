package status

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
	"github.com/g-wilson/seba/internal/storage"
)

type Function struct {
	Storage storage.Storage
	Clients map[string]seba.Client
}

type StatusResponse struct {
	UserID               string   `json:"user_id"`
	ClientID             string   `json:"client_id"`
	SecondFactorVerified bool     `json:"second_factor_verified"`
	Scopes               []string `json:"scopes"`
}

func (f *Function) Do(ctx context.Context) (*StatusResponse, error) {
	id := idcontext.GetIdentityContext(ctx)
	if !id.Exists() {
		return nil, seba.ErrNoAuthentication
	}

	_, ok := f.Clients[id.ClientID]
	if !ok {
		return nil, seba.ErrNoAuthentication
	}

	user, err := f.Storage.GetUserByID(ctx, id.UserID)
	if err != nil {
		return nil, err
	}
	if user.RemovedAt != nil {
		return nil, seba.ErrNoAuthentication
	}

	return &StatusResponse{
		UserID:               id.UserID,
		ClientID:             id.ClientID,
		SecondFactorVerified: id.SecondFactorVerified,
		Scopes:               id.Scopes,
	}, nil
}
