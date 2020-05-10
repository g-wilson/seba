package seba

import (
	"time"

	"github.com/g-wilson/runtime"
	"github.com/g-wilson/runtime/hand"
)

const (
	// ScopeSebaAdmin identifies an access token with user management permissions
	ScopeSebaAdmin = "seba:admin"

	GrantTypeEmailToken   = "email_token"
	GrantTypeInviteToken  = "invite_token"
	GrantTypeRefreshToken = "refresh_token"

	APIGatewayClient = "client_awsapigateway"
)

var (
	ErrAccessDenied         = hand.New(runtime.ErrCodeAccessDenied)
	ErrCreatingEmail        = hand.New("create_email_failed")
	ErrSendingEmail         = hand.New("send_email_failed")
	ErrUserNotFound         = hand.New("user_not_found")
	ErrNotSupportedByClient = hand.New("not_supported_by_client")
	ErrPKCEVerifierRequired = hand.New("pkce_verifier_required")
	ErrPKCEChallengeFailed  = hand.New("code_challenge_failed")
	ErrUnsupportedGrantType = hand.New("unsupported_grant_type")
	ErrClientNotFound       = hand.New("client_not_found")
	ErrClientIDMismatch     = hand.New("client_id_mismatch")
	ErrAuthnExpired         = hand.New("authn_expired")
	ErrAuthnAlreadyVerified = hand.New("authn_already_verified")
	ErrAuthnRevoked         = hand.New("authn_revoked")
	ErrRefreshTokenUsed     = hand.New("refresh_token_already_used")
	ErrInviteExpired        = hand.New("invite_expired")
	ErrUserAlreadyExists    = hand.New("user_already_exists")
)

type Client struct {
	ID                       string
	InviteConsumptionEnabled bool
	EmailAuthenticationURL   string
	DefaultScopes            []string
}

type Credentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
