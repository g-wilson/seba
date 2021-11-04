package dynamo

import (
	"fmt"
	"time"

	"github.com/g-wilson/seba"
	"github.com/segmentio/ksuid"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/guregu/dynamo"
)

type TypePrefix string

const (
	TypePrefixAuthentication     = TypePrefix("authn")
	TypePrefixRefreshToken       = TypePrefix("reftok")
	TypePrefixUser               = TypePrefix("user")
	TypePrefixEmail              = TypePrefix("email")
	TypePrefixWebauthnChallenge  = TypePrefix("wanchal")
	TypePrefixWebauthnCredential = TypePrefix("wancred")
	TypePrefixGoogleVerification = TypePrefix("googleverif")
)

type Params struct {
	AWSSession *session.Session
	AWSConfig  *aws.Config
	TableName  string
}

// DynamoStorage meets the seba.Storage interface
type DynamoStorage struct {
	db    *dynamo.DB
	table string
}

func New(cfg Params) *DynamoStorage {
	db := dynamo.New(cfg.AWSSession, cfg.AWSConfig)

	return &DynamoStorage{
		db:    db,
		table: cfg.TableName,
	}
}

func generateID(t TypePrefix) string {
	return fmt.Sprintf("%s_%s", t, ksuid.New().String())
}

type Authentication struct {
	ID            string     `dynamo:"id"`
	Email         string     `dynamo:"relation"`
	HashedCode    string     `dynamo:"lookup"`
	CreatedAt     time.Time  `dynamo:"created_at,unixtime"`
	VerifiedAt    *time.Time `dynamo:"verified_at,unixtime"`
	RevokedAt     *time.Time `dynamo:"revoked_at,unixtime"`
	ClientID      string     `dynamo:"client_id"`
	PKCEChallenge string     `dynamo:"pkce_challenge"`
}

func (a Authentication) ToApp() seba.Authentication {
	return seba.Authentication{
		ID:            a.ID,
		Email:         a.Email,
		HashedCode:    a.HashedCode,
		CreatedAt:     a.CreatedAt,
		VerifiedAt:    a.VerifiedAt,
		RevokedAt:     a.RevokedAt,
		ClientID:      a.ClientID,
		PKCEChallenge: a.PKCEChallenge,
	}
}

type RefreshToken struct {
	ID               string     `dynamo:"id"`
	UserID           string     `dynamo:"relation"`
	HashedToken      string     `dynamo:"lookup"`
	CreatedAt        time.Time  `dynamo:"created_at,unixtime"`
	UsedAt           *time.Time `dynamo:"used_at,unixtime"`
	ClientID         string     `dynamo:"client_id"`
	AuthenticationID *string    `dynamo:"authentication_id"`
}

func (r RefreshToken) ToApp() seba.RefreshToken {
	return seba.RefreshToken{
		ID:               r.ID,
		UserID:           r.UserID,
		HashedToken:      r.HashedToken,
		CreatedAt:        r.CreatedAt,
		UsedAt:           r.UsedAt,
		ClientID:         r.ClientID,
		AuthenticationID: r.AuthenticationID,
	}
}

type User struct {
	ID        string     `dynamo:"id"`
	CreatedAt time.Time  `dynamo:"created_at,unixtime"`
	RemovedAt *time.Time `dynamo:"removed_at,unixtime"`

	Relation string `dynamo:"relation"` // unused but must be set
}

func (u User) ToApp() seba.User {
	return seba.User{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		RemovedAt: u.RemovedAt,
	}
}

type Email struct {
	ID        string     `dynamo:"id"`
	Email     string     `dynamo:"lookup"`
	UserID    string     `dynamo:"relation"`
	CreatedAt time.Time  `dynamo:"created_at,unixtime"`
	RemovedAt *time.Time `dynamo:"removed_at,unixtime"`
}

func (e Email) ToApp() seba.Email {
	return seba.Email{
		ID:        e.ID,
		Email:     e.Email,
		UserID:    e.UserID,
		CreatedAt: e.CreatedAt,
		RemovedAt: e.RemovedAt,
	}
}

type WebauthnCredential struct {
	ID              string     `dynamo:"id"`
	UserID          string     `dynamo:"relation"`
	CreatedAt       time.Time  `dynamo:"created_at,unixtime"`
	RemovedAt       *time.Time `dynamo:"removed_at,unixtime"`
	Name            string     `dynamo:"name"`
	CredentialID    string     `dynamo:"lookup_value"`
	PublicKey       string     `dynamo:"public_key"`
	AttestationType string     `dynamo:"attestation_type"`
	AAGUID          string     `dynamo:"aaguid"`
	UserVerified    bool       `dynamo:"user_verified"`
	SignCount       int        `dynamo:"sign_count"`
}

func (c WebauthnCredential) ToApp() seba.WebauthnCredential {
	return seba.WebauthnCredential{
		ID:              c.ID,
		UserID:          c.UserID,
		CreatedAt:       c.CreatedAt,
		RemovedAt:       c.RemovedAt,
		Name:            c.Name,
		CredentialID:    c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		AAGUID:          c.AAGUID,
		UserVerified:    c.UserVerified,
		SignCount:       c.SignCount,
	}
}

type WebauthnChallenge struct {
	ID            string    `dynamo:"id"`
	UserID        string    `dynamo:"user_id"`
	SessionID     string    `dynamo:"session_id"`
	CreatedAt     time.Time `dynamo:"created_at,unixtime"`
	ChallengeType string    `dynamo:"challenge_type"`
	Challenge     string    `dynamo:"challenge"`
	CredentialIDs []string  `dynamo:"credential_ids,set"`
}

func (c WebauthnChallenge) ToApp() seba.WebauthnChallenge {
	return seba.WebauthnChallenge{
		ID:            c.ID,
		UserID:        c.UserID,
		SessionID:     c.SessionID,
		CreatedAt:     c.CreatedAt,
		ChallengeType: c.ChallengeType,
		Challenge:     c.Challenge,
		CredentialIDs: c.CredentialIDs,
	}
}

type GoogleVerification struct {
	ID        string    `dynamo:"id"`
	CreatedAt time.Time `dynamo:"created_at,unixtime"`
	Nonce     string    `dynamo:"nonce"`
	Subject   string    `dynamo:"relation"`
	Issuser   string    `dynamo:"iss"`
	Audience  string    `dynamo:"aud"`
}
