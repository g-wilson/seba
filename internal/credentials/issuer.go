package credentials

import (
	"context"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"

	"golang.org/x/sync/errgroup"
)

type Issuer struct {
	storage     storage.Storage
	credentials *Generator
}

func NewIssuer(storage storage.Storage, creds *Generator) *Issuer {
	return &Issuer{
		storage:     storage,
		credentials: creds,
	}
}

func (i *Issuer) Issue(ctx context.Context, user seba.UserExtended, client seba.Client, rootGrantID string) (seba.Credentials, error) {
	creds := seba.Credentials{}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if client.EnableRefreshTokenGrant && client.RefreshTokenTTL > 0 {
			rt, err := i.credentials.CreateRefreshToken(gctx, user.ToBasicUser(), client, rootGrantID)
			if err != nil {
				return err
			}

			_, err = i.storage.CreateRefreshToken(gctx, user.ID, client.ID, rt.HashedValue(), rootGrantID)
			if err != nil {
				return err
			}

			creds.RefreshToken = rt.Value()
		}

		return nil
	})

	g.Go(func() error {
		at, err := i.credentials.NewAccessToken(user.ToBasicUser(), client).Sign()
		if err != nil {
			return err
		}

		creds.AccessToken = at

		return nil
	})

	g.Go(func() error {
		idt, err := i.credentials.NewIDToken(user.ToBasicUser(), client).
			WithEmails(user.Emails).
			WithSecondFactor(user.SecondFactorEnrolled).
			Sign()
		if err != nil {
			return err
		}

		creds.IDToken = idt

		return nil
	})

	err := g.Wait()
	if err != nil {
		return seba.Credentials{}, err
	}

	return creds, nil
}
