package storage

import (
	"context"
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
)

const (
	TypePrefixAuthentication = "authn"
	TypePrefixRefreshToken   = "reftok"
	TypePrefixUser           = "user"
	TypePrefixEmail          = "email"
)

func generateID(typePrefix string) string {
	return fmt.Sprintf("%s_%s", typePrefix, uuid.NewV4().String())
}

type Authentication struct {
	ID            string     `json:"id" dynamo:"id"`
	Email         string     `json:"email" dynamo:"relation"`
	HashedCode    string     `json:"hashed_code" dynamo:"lookup_value"`
	CreatedAt     time.Time  `json:"created_at" dynamo:"created_at,unixtime"`
	VerifiedAt    *time.Time `json:"verified_at" dynamo:"verified_at,unixtime"`
	RevokedAt     *time.Time `json:"revoked_at" dynamo:"revoked_at,unixtime"`
	ClientID      string     `json:"client_id" dynamo:"client_id"`
	PKCEChallenge string     `json:"pkce_challenge" dynamo:"pkce_challenge"`
}

type RefreshToken struct {
	ID               string     `json:"id" dynamo:"id"`
	UserID           string     `json:"user_id" dynamo:"relation"`
	HashedToken      string     `json:"hashed_token" dynamo:"lookup_value"`
	CreatedAt        time.Time  `json:"created_at" dynamo:"created_at,unixtime"`
	UsedAt           *time.Time `json:"used_at" dynamo:"used_at,unixtime"`
	ClientID         string     `json:"client_id" dynamo:"client_id"`
	AuthenticationID *string    `json:"authentication_id" dynamo:"authentication_id"`
}

type User struct {
	ID        string     `json:"id" dynamo:"id"`
	CreatedAt time.Time  `json:"created_at" dynamo:"created_at,unixtime"`
	RemovedAt *time.Time `json:"removed_at" dynamo:"removed_at,unixtime"`

	Relation string `json:"-" dynamo:"relation"` // urgh
}

type Email struct {
	ID        string     `json:"id" dynamo:"id"`
	Email     string     `json:"email" dynamo:"lookup_value"`
	UserID    string     `json:"user_id" dynamo:"relation"`
	CreatedAt time.Time  `json:"created_at" dynamo:"created_at,unixtime"`
	RemovedAt *time.Time `json:"removed_at" dynamo:"removed_at,unixtime"`
}

type WebauthnCredential struct {
	ID              string     `json:"id" dynamo:"id"`
	UserID          string     `json:"user_id" dynamo:"relation"`
	CreatedAt       time.Time  `json:"created_at" dynamo:"created_at,unixtime"`
	RemovedAt       *time.Time `json:"removed_at" dynamo:"removed_at,unixtime"`
	Name            string     `json:"name" dynamo:"name"`
	CredentialID    []byte     `json:"credential_id" dynamo:"credential_id"`
	PublicKey       []byte     `json:"public_key" dynamo:"public_key"`
	AttestationType string     `json:"attestation_type" dynamo:"attestation_type"`
	AAGUID          []byte     `json:"aaguid" dynamo:"aaguid"`
	SignCount       uint32     `json:"sign_count" dynamo:"sign_count"`
}

type WebauthnChallenge struct {
	ID             string    `json:"id" dynamo:"id"`
	RefreshTokenID string    `json:"refresh_token_id" dynamo:"relation"`
	CreatedAt      time.Time `json:"created_at" dynamo:"created_at,unixtime"`
	ExpiresAt      time.Time `json:"expires_at" dynamo:"expires_at"`
	ChallengeType  string    `json:"challenge_type" dynamo:"challenge_type"`
	Challenge      string    `json:"challenge" dynamo:"challenge"`
	CredentialIDs  [][]byte  `json:"credential_ids" dynamo:"credential_ids,set"`
}

type Storage interface {
	Setup() error

	CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (*Authentication, error)
	GetAuthenticationByID(ctx context.Context, authenticationID string) (*Authentication, error)
	GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (*Authentication, error)
	SetAuthenticationVerified(ctx context.Context, authenticationID, email string) error
	SetAuthenticationRevoked(ctx context.Context, authenticationID, email string) error
	ListPendingAuthentications(ctx context.Context, email string) ([]*Authentication, error)

	CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (*RefreshToken, error)
	GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (*RefreshToken, error)
	SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) error

	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUserEmails(ctx context.Context, userID string) ([]*Email, error)
	CreateUserWithEmail(ctx context.Context, emailAddress string) (*User, error)

	CreateWebauthnRegistrationChallenge(ctx context.Context, refTokID, challenge string) error
	CreateWebauthnVerificationChallenge(ctx context.Context, refTokID, challenge string, credentialIDs [][]byte) error
	GetWebauthnChallenge(ctx context.Context, refTokID string) (*WebauthnChallenge, error)

	ListUserWebauthnCredentials(ctx context.Context, userID string) ([]*WebauthnCredential, error)
	GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (*WebauthnCredential, error)
	CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType string, credentialID, publicKey, AAGUID []byte, signCount int) error
	UpdateWebauthnCredential(ctx context.Context, credentialID string, signCount uint32) error
}
