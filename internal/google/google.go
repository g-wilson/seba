package google

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

const GoogleIssuer = "https://accounts.google.com"

type Verifier interface {
	Verify(ctx context.Context, idToken string) (Claims, error)
}

type Claims struct {
	jwt.Claims

	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Azp           string `json:"azp"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

type Config struct {
	ClientID   string
	HTTPClient *http.Client
}

func NewVerifier(c Config) Verifier {
	return &GoogleVerifier{
		clientID:   c.ClientID,
		httpClient: c.HTTPClient,
	}
}

type GoogleVerifier struct {
	clientID   string
	httpClient *http.Client
}

func (v *GoogleVerifier) Verify(ctx context.Context, idToken string) (cl Claims, err error) {
	certs, err := v.getCertificates(ctx)
	if err != nil {
		err = fmt.Errorf("GoogleVerifier: certs: %w", err)
		return
	}

	parsed, err := jwt.ParseSigned(idToken)
	if err != nil {
		err = fmt.Errorf("GoogleVerifier: parse: %w", err)
		return
	}

	cl = Claims{}

	if err = parsed.Claims(certs, &cl); err != nil {
		err = fmt.Errorf("GoogleVerifier: claims: %w", err)
		return
	}

	err = cl.Validate(jwt.Expected{
		Issuer:   GoogleIssuer,
		Audience: jwt.Audience{v.clientID},
		Time:     time.Now(),
	})
	if err != nil {
		err = fmt.Errorf("GoogleVerifier: validate: %w", err)
		return
	}

	return
}
