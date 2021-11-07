package credentials

import (
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type AccessToken struct {
	signer jose.Signer
	client *seba.Client
	user   *seba.User
	claims *AccessTokenClaims
}

type AccessTokenClaims struct {
	ClientID             string `json:"cid"`
	Scope                string `json:"scope"`
	SecondFactorVerified bool   `json:"sfv"`

	jwt.Claims
}

func (g *Generator) NewAccessToken(user seba.User, client seba.Client) *AccessToken {
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

func (t *AccessToken) Elevate() *AccessToken {
	if !t.client.EnableAccessTokenElevation {
		return t
	}

	t.claims.SecondFactorVerified = true
	t.claims.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(t.client.ElevatedAccessTokenTTL) * time.Second))
	t.claims.Scope = strings.Join([]string{
		strings.Join(t.client.DefaultScopes, " "),
		strings.Join(t.client.ElevatedScopes, " "),
	}, " ")

	return t
}

func (t *AccessToken) Sign() (string, error) {
	tok, err := jwt.Signed(t.signer).
		Claims(t.claims).
		CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("credentials: AccessToken: Sign: %w", err)
	}

	return tok, nil
}
