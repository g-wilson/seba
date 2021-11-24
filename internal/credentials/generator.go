package credentials

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/token"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Generator struct {
	Issuer string

	signer jose.Signer
	token  token.Token
}

func NewGenerator(issuer string, signer jose.Signer, tokenGenerator token.Token) *Generator {
	return &Generator{
		Issuer: issuer,
		signer: signer,
		token:  tokenGenerator,
	}
}

func (g *Generator) CreateAccessToken(user seba.User, client seba.Client) *AccessToken {
	cl := &AccessTokenClaims{
		ClientID: client.ID,
		Scope:    strings.Join(client.DefaultScopes, " "),
		Claims: jwt.Claims{
			Subject:   user.ID,
			Issuer:    g.Issuer,
			Audience:  client.DefaultAudience,
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		},
	}

	if client.AccessTokenTTL > 0 {
		cl.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(client.AccessTokenTTL) * time.Second))
	}

	return &AccessToken{
		signer: g.signer,
		client: &client,
		user:   &user,
		claims: cl,
	}
}

func (g *Generator) CreateRefreshToken(ctx context.Context, user seba.User, client seba.Client, grantID string) (RefreshToken, error) {
	if !client.EnableRefreshTokenGrant {
		return RefreshToken{}, fmt.Errorf("credentials: CreateRefreshToken: client does not allow refresh tokens")
	}

	tok, err := g.token.Generate(32)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("credentials: CreateRefreshToken: %w", err)
	}

	return RefreshToken{
		UserID:   user.ID,
		ClientID: client.ID,
		GrantID:  grantID,
		value:    tok,
	}, nil
}

func (g *Generator) CreateIDToken(user seba.User, client seba.Client) *IDToken {
	return &IDToken{
		claims: &IDTokenClaims{
			Emails:               []string{},
			SecondFactorEnrolled: false,
			Claims: jwt.Claims{
				Subject:   user.ID,
				Issuer:    g.Issuer,
				Audience:  jwt.Audience{client.ID},
				IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
				NotBefore: jwt.NewNumericDate(time.Now().UTC()),
				Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(IDTokenTTL)),
			},
		},
	}
}
