package credentials

import (
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const IDTokenTTL = 3600 * time.Second

type IDToken struct {
	signer jose.Signer
	claims *IDTokenClaims
}

type IDTokenClaims struct {
	Emails               []string `json:"emails"`
	SecondFactorEnrolled bool     `json:"sfe"`

	jwt.Claims
}

func (g *Generator) NewIDToken(user seba.User, client seba.Client) *IDToken {
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

func (t *IDToken) WithEmails(emails []seba.Email) *IDToken {
	for _, em := range emails {
		t.claims.Emails = append(t.claims.Emails, em.Email)
	}

	return t
}

func (t *IDToken) WithSecondFactor(isEnrolled bool) *IDToken {
	t.claims.SecondFactorEnrolled = isEnrolled

	return t
}

func (t *IDToken) Sign() (string, error) {
	if t.signer == nil {
		return "", fmt.Errorf("credentials: IDToken: Sign: signer does not exist")
	}

	tok, err := jwt.Signed(t.signer).
		Claims(t.claims).
		CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("credentials: IDToken: Sign: %w", err)
	}

	return tok, nil
}
