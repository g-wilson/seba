package seba

import (
	"time"

	"github.com/g-wilson/runtime"
	"github.com/g-wilson/runtime/hand"
	"golang.org/x/oauth2"
)

const (
	// ScopeSebaAdmin identifies an access token with user management permissions
	ScopeSebaAdmin = "seba:admin"

	GrantTypeEmailToken   = "email_token"
	GrantTypeInviteToken  = "invite_token"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeGoogle       = "google_authz_code"

	APIGatewayClient = "client_awsapigateway"
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

	ErrAccountNotFound = hand.New("account_not_found")

	ErrInviteExpired  = hand.New("invite_expired")
	ErrInviteNotFound = hand.New("invite_not_found")
	ErrInviteConsumed = hand.New("invite_already_consumed")
)

// Client represents one of your applications, e.g. your iOS app
type Client struct {
	// Set a unique ID for your client. This will be the audience parameter in the access token JWT.
	ID string

	// DefaultScopes is the list of scope strings to be issued in the access token JWT.
	DefaultScopes []string

	// EmailAuthenticationURL is the callback URL for magic link style authentication emails. Leave empty to disable email_token grant type.
	EmailAuthenticationURL string

	// RefreshTokenTTL is a duration during which a refresh_token grant will be valid. Set to zero to disable refresh_token grant type.
	RefreshTokenTTL time.Duration

	// EnableInviteConsumption enables invite_token grant type
	EnableInviteConsumption bool

	// GoogleConfig is used to create the google API client to exchange the authorization code
	GoogleConfig *oauth2.Config
}

func (c *Client) GoogleGrantEnabled() bool {
	return c.GoogleConfig != nil
}

func (c *Client) RefreshGrantEnabed() bool {
	return c.RefreshTokenTTL > 0*time.Second
}

func (c *Client) EmailGrantEnabled() bool {
	return c.EmailAuthenticationURL == ""
}

func (c *Client) InviteGrantEnabled() bool {
	return c.EnableInviteConsumption
}

type Credentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
}

type AuthenticateRequest struct {
	GrantType    string  `json:"grant_type"`
	Code         string  `json:"code"`
	ClientID     string  `json:"client_id"`
	PKCEVerifier *string `json:"pkce_verifier,omitempty"`
}

type AuthenticateResponse struct {
	*Credentials
}

type SendAuthenticationEmailRequest struct {
	Email         string `json:"email"`
	State         string `json:"state"`
	ClientID      string `json:"client_id"`
	PKCEChallenge string `json:"pkce_challenge"`
}

type ConsumeInviteRequest struct {
	Token string `json:"token"`
}

type ConsumeInviteResponse struct {
	UserID    string `json:"user_id"`
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
}

type CreateAccountResponse struct {
	AccountID string `json:"account_id"`
}

type SendInviteEmailRequest struct {
	Email     string `json:"email"`
	AccountID string `json:"account_id"`
}

type SendInviteEmailResponse struct {
	InviteID string `json:"invite_id"`
}

type GetAccountRequest struct {
	AccountID string `json:"account_id"`
}

type GetAccountResponse struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	Users     []AccountUser `json:"users"`
}

type AccountUser struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

type GetUserByEmailRequest struct {
	Email string `json:"email"`
}

type GetUserByEmailResponse struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"created_at"`
	AccountID string      `json:"account_id"`
	Emails    []UserEmail `json:"emails"`
}

type GetUserRequest struct {
	UserID string `json:"user_id"`
}

type GetUserResponse struct {
	ID        string      `json:"id"`
	CreatedAt time.Time   `json:"created_at"`
	AccountID string      `json:"account_id"`
	Emails    []UserEmail `json:"emails"`
}

type UserEmail struct {
	CreatedAt time.Time `json:"created_at"`
	Value     string    `json:"value"`
}
