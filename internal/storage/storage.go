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
	TypePrefixInvite         = "invite"
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

type Storage interface {
	Setup() error

	CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (ent *Authentication, err error)
	GetAuthenticationByID(ctx context.Context, authenticationID string) (ent *Authentication, err error)
	GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (ent *Authentication, err error)
	SetAuthenticationVerified(ctx context.Context, authenticationID, email string) (err error)
	SetAuthenticationRevoked(ctx context.Context, authenticationID, email string) (err error)
	ListPendingAuthentications(ctx context.Context, email string) (authns []Authentication, err error)

	CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (ent *RefreshToken, err error)
	GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (ent *RefreshToken, err error)
	SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) (err error)

	GetUserByID(ctx context.Context, userID string) (ent *User, err error)
	GetUserByEmail(ctx context.Context, email string) (ent *User, err error)
	ListUserEmails(ctx context.Context, userID string) (ems []Email, err error)
	CreateUserWithEmail(ctx context.Context, emailAddress string) (user *User, err error)
}
