package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"

	"github.com/g-wilson/runtime/logger"
	"golang.org/x/sync/errgroup"
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

type CredentialProvider interface {
	CreateForUser(ctx context.Context, user seba.User, client seba.Client, authnID *string) (*seba.Credentials, error)
	CreateForUserElevated(ctx context.Context, user seba.User, client seba.Client, authnID *string) (*seba.Credentials, error)
	CreateBasic(subject string, client seba.Client) (string, error)
}

// Credentials holds dependencies and meets the CredentialProvider interface
type Credentials struct {
	Issuer  string
	Signer  jose.Signer
	Storage storage.Storage
	Token   token.Token
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

// CreateForUser creates and signs a JWT for the provided user, client and authentication ID
// Scopes are always defined on the client config. oAuth style scope granting is not supported.
func (c *Credentials) CreateForUser(ctx context.Context, user seba.User, client seba.Client, authnID *string) (*seba.Credentials, error) {
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
		return nil, fmt.Errorf("credentials: %w", err)
	}

	idToken, err := c.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}

	creds := &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.EnableRefreshTokenGrant {
		refreshToken, err := c.Token.Generate(32)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}

		logger.FromContext(ctx).Entry().Debugf("refresh_token: %s", refreshToken)

		_, err = c.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}

		creds.RefreshToken = refreshToken
	}

	return creds, nil
}

// CreateForUserElevated is the same as CreateForUser but adds claims from a webauthn
func (c *Credentials) CreateForUserElevated(ctx context.Context, user seba.User, client seba.Client, authnID *string) (*seba.Credentials, error) {
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
		return nil, fmt.Errorf("credentials: %w", err)
	}

	idToken, err := c.createIDToken(ctx, user.ID, basicClaims)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}

	creds := &seba.Credentials{
		AccessToken: accessToken,
		IDToken:     idToken,
	}

	if client.EnableRefreshTokenGrant {
		refreshToken, err := c.Token.Generate(32)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}

		logger.FromContext(ctx).Entry().Debugf("refresh_token: %s", refreshToken)

		_, err = c.Storage.CreateRefreshToken(ctx, user.ID, client.ID, sha256Hex(refreshToken), authnID)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
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
	if err != nil {
		return "", fmt.Errorf("credentials: %w", err)
	}

	return accessToken, nil
}

func (c *Credentials) createIDToken(ctx context.Context, userID string, claims jwt.Claims) (string, error) {
	idTokenClaims := &IDTokenClaims{
		Emails: []string{},
		Claims: claims,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		emails, err := c.Storage.ListUserEmails(gctx, userID)
		if err != nil {
			return err
		}
		for _, em := range emails {
			idTokenClaims.Emails = append(idTokenClaims.Emails, em.Email)
		}

		return nil
	})

	g.Go(func() error {
		storedCreds, err := c.Storage.ListUserWebauthnCredentials(gctx, userID)
		if err != nil {
			return err
		}

		idTokenClaims.SecondFactorEnrolled = len(storedCreds) > 0

		return nil
	})

	err := g.Wait()
	if err != nil {
		return "", err
	}

	idToken, err := jwt.Signed(c.Signer).
		Claims(idTokenClaims).
		CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("credentials: %w", err)
	}

	return idToken, nil
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
