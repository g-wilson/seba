package app

import (
	"context"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"gopkg.in/square/go-jose.v2/jwt"
)

type AccessTokenClaims struct {
	AccountID string `json:"aid"`
	ClientID  string `json:"cid"`
	Scope     string `json:"scope"`

	jwt.Claims
}

type IDTokenClaims struct {
	Emails    []string `json:"emails"`
	AccountID string   `json:"aid"`

	jwt.Claims
}

func (a *App) CreateCredentials(ctx context.Context, userID string, client Client, authnID *string) (creds *seba.Credentials, err error) {
	user, err := a.GetUser(ctx, &seba.GetUserRequest{UserID: userID})
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateToken(32)
	if err != nil {
		return
	}

	a.Logger.Debugf("refresh_token: %s", refreshToken)

	_, err = a.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
	if err != nil {
		return
	}

	basicClaims := jwt.Claims{
		Subject:   user.ID,
		Issuer:    a.jwtConfig.Issuer,
		Audience:  jwt.Audience{apiGatewayClient},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(60 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := &AccessTokenClaims{
		AccountID: user.AccountID,
		ClientID:  client.ID,
		Scope:     strings.Join(client.DefaultScopes, " "),
		Claims:    basicClaims,
	}
	accessToken, err := jwt.Signed(a.jwtConfig.Signer).
		Claims(claims).
		CompactSerialize()
	if err != nil {
		return
	}

	strEmails := []string{}
	for _, em := range user.Emails {
		strEmails = append(strEmails, em.Value)
	}

	idToken, err := jwt.Signed(a.jwtConfig.Signer).
		Claims(&IDTokenClaims{
			Emails:    strEmails,
			AccountID: user.AccountID,
			Claims:    basicClaims,
		}).
		CompactSerialize()
	if err != nil {
		return
	}

	return &seba.Credentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
	}, nil
}

// CreateClientAccessToken can be used to mint a one-off access token. Typical usage would be for local development or for service-to-service auth.
func (a *App) CreateClientAccessToken(subject string, scopes []string) (string, error) {
	basicClaims := jwt.Claims{
		Subject:   subject,
		Issuer:    a.jwtConfig.Issuer,
		Audience:  jwt.Audience{apiGatewayClient},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(86400 * 365 * time.Second)),
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
