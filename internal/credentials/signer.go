package credentials

import (
	"errors"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

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
