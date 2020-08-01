package app

import (
	"context"
	"strings"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"

	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// UserCredentialsTTL is the duration of validity for a user access token
	UserCredentialsTTL = 180 * time.Minute

	// ElevatedUserCredentialsTTL is the duration of validity for an elevated user access token
	ElevatedUserCredentialsTTL = 60 * time.Minute

	// BasicCredentialsTTL is the duration of validity for a basic access token
	BasicCredentialsTTL = 86400 * 365 * time.Second
)

// AccessTokenClaims type is used to marshal the access token JWT claims payload
type AccessTokenClaims struct {
	ClientID string `json:"cid"`
	Scope    string `json:"scope"`

	SecondFactor bool `json:"2fa"`
	UserVerified bool `json:"2uv,omitempty"`

	jwt.Claims
}

// IDTokenClaims type is used to marshal the id token JWT claims payload
type IDTokenClaims struct {
	Emails []string `json:"emails"`

	jwt.Claims
}

// CreateUserCredentials creates and signs a JWT for the provided user, client and authentication ID
// Scopes are always defined on the client config. oAuth style scope granting is not supported.
func (a *App) CreateUserCredentials(ctx context.Context, user *storage.User, client seba.Client, authnID *string) (creds *seba.Credentials, err error) {
	basicClaims := jwt.Claims{
		Subject:   user.ID,
		Issuer:    a.jwtConfig.Issuer,
		Audience:  jwt.Audience{seba.APIGatewayClient},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(UserCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := &AccessTokenClaims{
		ClientID: client.ID,
		Scope:    strings.Join(client.DefaultScopes, " "),
		Claims:   basicClaims,
	}
	accessToken, err := jwt.Signed(a.jwtConfig.Signer).
		Claims(claims).
		CompactSerialize()
	if err != nil {
		return
	}

	idToken, err := a.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, err
	}

	creds = &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.RefreshGrantEnabed() {
		refreshToken, err := token.GenerateToken(32)
		if err != nil {
			return nil, err
		}

		a.Logger.Debugf("refresh_token: %s", refreshToken)

		_, err = a.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, err
		}

		creds.RefreshToken = refreshToken
	}

	return creds, nil
}

// CreateElevatedUserCredentials is the same as CreateUserCredentials but adds claims from a webauthn
func (a *App) CreateElevatedUserCredentials(ctx context.Context, user *storage.User, client seba.Client, authnID *string, isUserVerified bool) (creds *seba.Credentials, err error) {
	basicClaims := jwt.Claims{
		Subject:   user.ID,
		Issuer:    a.jwtConfig.Issuer,
		Audience:  jwt.Audience{seba.APIGatewayClient},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(ElevatedUserCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := &AccessTokenClaims{
		ClientID:     client.ID,
		Scope:        strings.Join(client.DefaultScopes, " "),
		SecondFactor: true,
		UserVerified: isUserVerified,
		Claims:       basicClaims,
	}
	accessToken, err := jwt.Signed(a.jwtConfig.Signer).
		Claims(claims).
		CompactSerialize()
	if err != nil {
		return
	}

	idToken, err := a.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, err
	}

	creds = &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.RefreshGrantEnabed() {
		refreshToken, err := token.GenerateToken(32)
		if err != nil {
			return nil, err
		}

		a.Logger.Debugf("refresh_token: %s", refreshToken)

		_, err = a.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, err
		}

		creds.RefreshToken = refreshToken
	}

	return creds, nil
}

// CreateBasicCredentials creates and signs a JWT for a provided subject and with a provided set of scopes
// Current usage is for local development or for service-to-service auth
func (a *App) CreateBasicCredentials(subject string, scopes []string) (string, error) {
	basicClaims := jwt.Claims{
		Subject:   subject,
		Issuer:    a.jwtConfig.Issuer,
		Audience:  jwt.Audience{seba.APIGatewayClient},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(BasicCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := AccessTokenClaims{
		Scope:  strings.Join(scopes, " "),
		Claims: basicClaims,
	}
	accessToken, err := jwt.Signed(a.jwtConfig.Signer).
		Claims(claims).
		CompactSerialize()

	return accessToken, err
}

func (a *App) createIDToken(ctx context.Context, userID string, claims jwt.Claims) (string, error) {
	emails, err := a.Storage.ListUserEmails(ctx, userID)
	if err != nil {
		return "", err
	}
	strEmails := []string{}
	for _, em := range emails {
		strEmails = append(strEmails, em.Email)
	}

	return jwt.Signed(a.jwtConfig.Signer).
		Claims(&IDTokenClaims{
			Emails: strEmails,
			Claims: claims,
		}).
		CompactSerialize()
}
