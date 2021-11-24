package credentials

import (
	"context"

	"github.com/g-wilson/seba"

	"golang.org/x/sync/errgroup"
)

type Issuer struct {
	generator               *Generator
	persistRefreshTokenFunc PersistRefreshTokenFunc
}

type PersistRefreshTokenFunc func(ctx context.Context, userID, clientID, hashedToken, grantID string) (seba.RefreshToken, error)

func NewIssuer(gen *Generator, pFn PersistRefreshTokenFunc) *Issuer {
	return &Issuer{
		generator:               gen,
		persistRefreshTokenFunc: pFn,
	}
}

func (i *Issuer) Issue(ctx context.Context, user seba.UserExtended, client seba.Client, rootGrantID string) (seba.Credentials, error) {
	creds := seba.Credentials{}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if client.EnableRefreshTokenGrant && client.RefreshTokenTTL > 0 {
			rt, err := i.generator.CreateRefreshToken(gctx, user.ToBasicUser(), client, rootGrantID)
			if err != nil {
				return err
			}

			_, err = i.persistRefreshTokenFunc(gctx, user.ID, client.ID, rt.HashedValue(), rootGrantID)
			if err != nil {
				return err
			}

			creds.RefreshToken = rt.Value()
		}

		return nil
	})

	g.Go(func() error {
		at, err := i.generator.CreateAccessToken(user.ToBasicUser(), client).Sign()
		if err != nil {
			return err
		}

		creds.AccessToken = at

		return nil
	})

	g.Go(func() error {
		idt, err := i.generator.CreateIDToken(user.ToBasicUser(), client).
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
