package credentials

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Verifier struct {
	Issuer string

	keyset jose.JSONWebKeySet
}

func (v *Verifier) Verify(accessToken string, client seba.Client, dest interface{}) error {
	parsed, err := jwt.ParseSigned(accessToken)
	if err != nil {
		return fmt.Errorf("credentials: Verifier: VerifyAccessToken: %w", err)
	}

	switch dest.(type) {
	case AccessTokenClaims:
	case IDTokenClaims:
	default:
		return fmt.Errorf("credentials: Verifier: VerifyAccessToken: destination %s is not a supported type", reflect.TypeOf(dest).Name())
	}

	if err = parsed.Claims(v.keyset, &dest); err != nil {
		return fmt.Errorf("credentials: Verifier: VerifyAccessToken: %w", err)
	}

	switch dest.(type) {
	case AccessTokenClaims:
		err = dest.(AccessTokenClaims).Validate(jwt.Expected{
			Issuer:   v.Issuer,
			Audience: client.DefaultAudience,
			Time:     time.Now(),
		})
		if err != nil {
			return fmt.Errorf("credentials: Verifier: VerifyAccessToken: %w", err)
		}
	case IDTokenClaims:
		err = dest.(AccessTokenClaims).Validate(jwt.Expected{
			Issuer:   v.Issuer,
			Audience: jwt.Audience{client.ID},
			Time:     time.Now(),
		})
		if err != nil {
			return fmt.Errorf("credentials: Verifier: VerifyAccessToken: %w", err)
		}
	}

	return nil
}

func MustCreateVerifier(issuer, keysetJSON string) Verifier {
	keys := jose.JSONWebKeySet{}

	err := json.NewDecoder(strings.NewReader(keysetJSON)).Decode(&keys)
	if err != nil {
		panic(fmt.Errorf("credentials: error creating jwt verifier: %w", err))
	}

	for _, k := range keys.Keys {
		if !k.Valid() {
			panic(fmt.Errorf("keydecoder: invalid key: %s", k.KeyID))
		}
	}

	return Verifier{Issuer: issuer, keyset: keys}
}
