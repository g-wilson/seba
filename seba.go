package seba

import (
	"time"

	"github.com/g-wilson/runtime"
	"github.com/g-wilson/runtime/hand"
)

const (
	GrantTypeEmailToken   = "email_token"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeGoogle       = "google_id_token"
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

	ErrGoogleVerifyFailed    = hand.New("google_verify_failed")
	ErrGoogleAlreadyVerified = hand.New("google_already_verified")

	ErrUserNotFound = hand.New("user_not_found")

	ErrWebauthnChallengeNotFound  = hand.New("webauthn_challenge_not_found")
	ErrWebauthnCredentialNotFound = hand.New("webauthn_credential_not_found")
)

// Client represents one of your applications, e.g. your iOS app
type Client struct {
	// Set a unique ID for your client. This will be the audience parameter in the access token JWT.
	ID string

	// DefaultScopes is the list of scope strings to be issued in the access token JWT.
	DefaultScopes []string

	// DefaultAudience is the list of aud strings to be issued in the access token JWT.
	DefaultAudience []string

	// AccessTokenTTL is the validity lifetime of the access token JWT in seconds. Must be positive.
	AccessTokenTTL int

	// EnableEmailGrant will enable secure link sent via email functionality.
	EnableEmailGrant bool

	// EmailLinkBaseURL is the base URL of the secure link sent via email. It must not already have a query string.
	EmailLinkBaseURL string

	// EnableGoogleGrant will enable sign in with Google functionality.
	EnableGoogleGrant bool

	// EnableRefreshTokenGrant will enable session extension via refresh tokens.
	EnableRefreshTokenGrant bool

	// RefreshTokenTTL is a duration during which a refresh_token grant will be valid.
	RefreshTokenTTL time.Duration

	// EnableWebauthnRegistration will enable the client to register hardware security keys
	EnableWebauthnRegistration bool

	// EnableAccessTokenElevation will enable the client to elevate scopes if a Webauthn challenge is completed
	EnableAccessTokenElevation bool

	// ElevatedAccessTokenTTL is the validity lifetime of the elevated access token JWT in seconds. Must be positive.
	ElevatedAccessTokenTTL int

	// ElevatedScopes is the list of scope strings to be issued in the elevated access token JWT (when a second-factor verification took place).
	ElevatedScopes []string
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
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	HashedToken string     `json:"hashed_token"`
	CreatedAt   time.Time  `json:"created_at"`
	UsedAt      *time.Time `json:"used_at"`
	ClientID    string     `json:"client_id"`
	GrantID     string     `json:"grant_id"`
}

type User struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	RemovedAt *time.Time `json:"removed_at"`
}

type UserExtended struct {
	ID                   string     `json:"id"`
	CreatedAt            time.Time  `json:"created_at"`
	RemovedAt            *time.Time `json:"removed_at"`
	Emails               []Email    `json:"emails"`
	SecondFactorEnrolled bool       `json:"second_factor_enrolled"`
}

func (u UserExtended) ToBasicUser() User {
	return User{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		RemovedAt: u.RemovedAt,
	}
}

type Email struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	UserID    string     `json:"user_id"`
	CreatedAt time.Time  `json:"created_at"`
	RemovedAt *time.Time `json:"removed_at"`
}

type WebauthnCredential struct {
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	CreatedAt       time.Time  `json:"created_at"`
	RemovedAt       *time.Time `json:"removed_at"`
	Name            string     `json:"name"`
	CredentialID    string     `json:"credential_id"`
	PublicKey       string     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          string     `json:"aaguid"`
	UserVerified    bool       `json:"user_verified"`
	SignCount       int        `json:"sign_count"`
}

type WebauthnChallenge struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	SessionID     string    `json:"session_id"`
	CreatedAt     time.Time `json:"created_at"`
	ChallengeType string    `json:"challenge_type"`
	Challenge     string    `json:"challenge"`
	CredentialIDs []string  `json:"credential_ids"`
}

type GoogleVerification struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Nonce     string    `json:"nonce"`
	Subject   string    `json:"relation"`
	Issuser   string    `json:"iss"`
	Audience  string    `json:"aud"`
}
