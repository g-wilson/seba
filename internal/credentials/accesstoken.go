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
