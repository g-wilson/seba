package credentials

import (
	"errors"
	"fmt"

	"github.com/g-wilson/seba/internal/token"

	"gopkg.in/square/go-jose.v2"
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

func MustCreateSigner(keyString string) jose.Signer {
	key := jose.JSONWebKey{}
	err := key.UnmarshalJSON([]byte(keyString))
	if err != nil {
		panic(fmt.Errorf("credentials: error parsing private key: %w", err))
	}
	if !key.Valid() {
		panic(errors.New("credentials: key invalid"))
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		panic(fmt.Errorf("credentials: error creating jwt signer: %w", err))
	}

	return signer
}
