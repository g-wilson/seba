package seba

import (
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	webauthnProtocol "github.com/duo-labs/webauthn/protocol"
	"github.com/g-wilson/runtime"
	"github.com/g-wilson/runtime/hand"
	"golang.org/x/oauth2"
)

const (
	// ScopeSebaAdmin identifies an access token with user management permissions
	ScopeSebaAdmin = "seba:admin"

	GrantTypeEmailToken   = "email_token"
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

	ErrWebauthnChallengeNotFound  = hand.New("webauthn_challenge_not_found")
	ErrWebauthnCredentialNotFound = hand.New("webauthn_credential_not_found")
)

// Config type is used as the argument to the app constructor
type Config struct {
	LogLevel  string
	LogFormat string

	AWSConfig       *aws.Config
	AWSSession      *session.Session
	DynamoTableName string

	ActuallySendEmails bool
	EmailConfig        EmailConfig

	JWTPrivateKey string
	JWTIssuer     string

	WebauthnDisplayName string
	WebauthnID          string

	Clients []Client
}

// EmailConfig type is a group of settings for emails
type EmailConfig struct {
	DefaultReplyAddress string
	DefaultFromAddress  string

	AuthnEmailSubject  string
	AuthnEmailTemplate *template.Template
}

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

	// GoogleConfig is used to create the google API client to exchange the authorization code. Leave empty to disable google_authz_code grant type.
	GoogleConfig *oauth2.Config

	// WebauthnOrigin is used to validate webauthn requests against a web page. Leave empty to disable webauthn functionality.
	WebauthnOrigin string
}

func (c *Client) GoogleGrantEnabled() bool {
	return c.GoogleConfig != nil
}

func (c *Client) RefreshGrantEnabed() bool {
	return c.RefreshTokenTTL > 0*time.Second
}

func (c *Client) EmailGrantEnabled() bool {
	return c.EmailAuthenticationURL != ""
}

func (c *Client) WebauthnEnabled() bool {
	return c.WebauthnOrigin != ""
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

type StartWebauthnRegistrationRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type StartWebauthnRegistrationResponse struct {
	ChallengeID        string                                              `json:"challenge_id"`
	AttestationOptions webauthnProtocol.PublicKeyCredentialCreationOptions `json:"attestation_options"`
}

type CompleteWebauthnRegistrationRequest struct {
	ChallengeID         string `json:"challenge_id"`
	AttestationResponse string `json:"attestation_response"`
}

type CompleteWebauthnRegistrationResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type StartWebauthnVerificationRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type StartWebauthnVerificationResponse struct {
	ChallengeID      string                                             `json:"challenge_id"`
	AssertionOptions webauthnProtocol.PublicKeyCredentialRequestOptions `json:"assertion_options"`
}

type CompleteWebauthnVerificationRequest struct {
	ChallengeID       string `json:"challenge_id"`
	AssertionResponse string `json:"assertion_response"`
}

type CompleteWebauthnVerificationResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}
