package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/g-wilson/runtime/logger"
	"gopkg.in/square/go-jose.v2"
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

// Credentials holds dependencies and meets the seba.CredentialProvider interface
type Credentials struct {
	Issuer  string
	Signer  jose.Signer
	Storage seba.Storage
	Token   seba.Token
}

// AccessTokenClaims type is used to marshal the access token JWT claims payload
type AccessTokenClaims struct {
	ClientID             string `json:"cid"`
	Scope                string `json:"scope"`
	SecondFactorVerified bool   `json:"sfv"`

	jwt.Claims
}

// IDTokenClaims type is used to marshal the id token JWT claims payload
type IDTokenClaims struct {
	Emails               []string `json:"emails"`
	SecondFactorEnrolled bool     `json:"sfe"`

	jwt.Claims
}

// CreateForUser creates and signs a JWT for the provided user, client and authentication ID
// Scopes are always defined on the client config. oAuth style scope granting is not supported.
func (c *Credentials) CreateForUser(ctx context.Context, user *seba.User, client seba.Client, authnID *string) (creds *seba.Credentials, err error) {
	basicClaims := jwt.Claims{
		Subject:   user.ID,
		Issuer:    c.Issuer,
		Audience:  client.DefaultAudience,
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(UserCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := &AccessTokenClaims{
		ClientID: client.ID,
		Scope:    strings.Join(client.DefaultScopes, " "),
		Claims:   basicClaims,
	}
	accessToken, err := jwt.Signed(c.Signer).
		Claims(claims).
		CompactSerialize()
	if err != nil {
		return
	}

	idToken, err := c.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, err
	}

	creds = &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.EnableRefreshTokenGrant {
		refreshToken, err := c.Token.Generate(32)
		if err != nil {
			return nil, err
		}

		logger.FromContext(ctx).Entry().Debugf("refresh_token: %s", refreshToken)

		_, err = c.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, err
		}

		creds.RefreshToken = refreshToken
	}

	return creds, nil
}

// CreateForUserElevated is the same as CreateForUser but adds claims from a webauthn
func (c *Credentials) CreateForUserElevated(ctx context.Context, user *seba.User, client seba.Client, authnID *string, isUserVerified bool) (creds *seba.Credentials, err error) {
	basicClaims := jwt.Claims{
		Subject:   user.ID,
		Issuer:    c.Issuer,
		Audience:  client.DefaultAudience,
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(ElevatedUserCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := AccessTokenClaims{
		ClientID:             client.ID,
		Scope:                strings.Join(client.DefaultScopes, " "),
		SecondFactorVerified: true,
		Claims:               basicClaims,
	}
	accessToken, err := jwt.Signed(c.Signer).
		Claims(claims).
		CompactSerialize()
	if err != nil {
		return
	}

	idToken, err := c.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, err
	}

	creds = &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.EnableRefreshTokenGrant {
		refreshToken, err := c.Token.Generate(32)
		if err != nil {
			return nil, err
		}

		logger.FromContext(ctx).Entry().Debugf("refresh_token: %s", refreshToken)

		_, err = c.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, err
		}

		creds.RefreshToken = refreshToken
	}

	return creds, nil
}

// CreateBasic creates and signs a JWT for a provided subject and with a provided set of scopes
// Current usage is for local development or for service-to-service auth
func (c *Credentials) CreateBasic(subject string, client seba.Client) (string, error) {
	basicClaims := jwt.Claims{
		Subject:   subject,
		Issuer:    c.Issuer,
		Audience:  client.DefaultAudience,
		Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(BasicCredentialsTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
	}
	claims := AccessTokenClaims{
		ClientID: client.ID,
		Scope:    strings.Join(client.DefaultScopes, " "),
		Claims:   basicClaims,
	}
	accessToken, err := jwt.Signed(c.Signer).
		Claims(claims).
		CompactSerialize()

	return accessToken, err
}

func (c *Credentials) createIDToken(ctx context.Context, userID string, claims jwt.Claims) (string, error) {
	idTokenClaims := &IDTokenClaims{
		Emails: []string{},
		Claims: claims,
	}

	emails, err := c.Storage.ListUserEmails(ctx, userID)
	if err != nil {
		return "", err
	}

	for _, em := range emails {
		idTokenClaims.Emails = append(idTokenClaims.Emails, em.Email)
	}

	return jwt.Signed(c.Signer).
		Claims(idTokenClaims).
		CompactSerialize()
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}