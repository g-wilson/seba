package seba

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/runtime"
	"github.com/g-wilson/runtime/hand"
	"github.com/segmentio/ksuid"
	"gopkg.in/square/go-jose.v2"
)

type TypePrefix string

const (
	TypePrefixAuthentication = TypePrefix("authn")
	TypePrefixRefreshToken   = TypePrefix("reftok")
	TypePrefixUser           = TypePrefix("user")
	TypePrefixEmail          = TypePrefix("email")
)

const (
	GrantTypeEmailToken   = "email_token"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeGoogle       = "google_authz_code"
)

var (
	ErrAccessDenied = hand.New(runtime.ErrCodeAccessDenied)

	ErrCreatingEmail = hand.New("create_email_failed")
	ErrSendingEmail  = hand.New("send_email_failed")

	ErrNotSupportedByClient = hand.New("not_supported_by_client")
	ErrPKCEVerifierRequired = hand.New("pkce_verifier_required")
	ErrPKCEChallengeFailed  = hand.New("code_challenge_failed")
	ErrUnsupportedGrantType = hand.New("unsupported_grant_type")
	ErrAuthnNotFound        = hand.New("authentication_not_found")

	ErrEmailNotVerified = hand.New("email_not_verified")
	ErrEmailTaken       = hand.New("email_taken")

	ErrClientNotFound   = hand.New("client_not_found")
	ErrClientIDMismatch = hand.New("client_id_mismatch")

	ErrAuthnExpired         = hand.New("authn_expired")
	ErrAuthnAlreadyVerified = hand.New("authn_already_verified")
	ErrAuthnRevoked         = hand.New("authn_revoked")

	ErrRefreshTokenNotFound = hand.New("refresh_token_not_found")
	ErrRefreshTokenUsed     = hand.New("refresh_token_already_used")
	ErrRefreshTokenExpired  = hand.New("refresh_token_expired")

	ErrUserNotFound      = hand.New("user_not_found")
	ErrUserAlreadyExists = hand.New("user_already_exists")
)

func GenerateID(t TypePrefix) string {
	return fmt.Sprintf("%s_%s", t, ksuid.New().String())
}

// Client represents one of your applications, e.g. your iOS app
type Client struct {
	// Set a unique ID for your client. This will be the audience parameter in the access token JWT.
	ID string

	// DefaultScopes is the list of scope strings to be issued in the access token JWT.
	DefaultScopes []string

	// DefaultAudience is the list of aud strings to be issued in the access token JWT.
	DefaultAudience []string

	// CallbackURL is the callback URL where the user will be redirected after authentication via magic link or google sign in.
	CallbackURL string

	// EnableEmailGrant will enable magic link functionality.
	EnableEmailGrant bool

	// EnableGoogleGrant will enable sign in with Google functionality.
	EnableGoogleGrant bool

	// EnableRefreshTokenGrant will enable session extension via refresh tokens.
	EnableRefreshTokenGrant bool

	// RefreshTokenTTL is a duration during which a refresh_token grant will be valid.
	RefreshTokenTTL time.Duration
}

type Credentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

type Authentication struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	HashedCode    string     `json:"hashed_code"`
	CreatedAt     time.Time  `json:"created_at"`
	VerifiedAt    *time.Time `json:"verified_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	ClientID      string     `json:"client_id"`
	PKCEChallenge string     `json:"pkce_challenge"`
}

type RefreshToken struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	HashedToken      string     `json:"hashed_token"`
	CreatedAt        time.Time  `json:"created_at"`
	UsedAt           *time.Time `json:"used_at"`
	ClientID         string     `json:"client_id"`
	AuthenticationID *string    `json:"authentication_id"`
}

type User struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	RemovedAt *time.Time `json:"removed_at"`

	Relation string `json:"-"`
}

type Email struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	RemovedAt *time.Time `json:"removed_at"`
}

type Token interface {
	Generate(length int) (string, error)
}

type Storage interface {
	CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (Authentication, error)
	GetAuthenticationByID(ctx context.Context, authenticationID string) (Authentication, error)
	GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (Authentication, error)
	SetAuthenticationVerified(ctx context.Context, authenticationID, email string) error
	SetAuthenticationRevoked(ctx context.Context, authenticationID, email string) error
	ListPendingAuthentications(ctx context.Context, email string) ([]Authentication, error)

	CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, reftokID string) (RefreshToken, error)
	GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (RefreshToken, error)
	SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) error

	GetUserByID(ctx context.Context, userID string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	ListUserEmails(ctx context.Context, userID string) ([]Email, error)
	CreateUserWithEmail(ctx context.Context, emailAddress string) (User, error)
}

type Emailer interface {
	SendAuthenticationEmail(ctx context.Context, emailAddress, linkURL string) error
}

type CredentialProvider interface {
	CreateForUser(ctx context.Context, user *User, client Client, authnID *string) (*Credentials, error)
	CreateForUserElevated(ctx context.Context, user *User, client Client, authnID *string, isUserVerified bool) (*Credentials, error)
	CreateBasic(subject string, client Client) (string, error)
}

type JWTKeyProvider interface {
	GetSigner() (jose.Signer, error)
	GetPublicKey() (jose.JSONWebKey, error)
}
