package dynamo

import (
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/guregu/dynamo"
)

type Params struct {
	IDGenerator func(t seba.TypePrefix) string
	AWSSession  *session.Session
	AWSConfig   *aws.Config
	TableName   string
}

// DynamoStorage meets the seba.Storage interface
type DynamoStorage struct {
	generateID func(t seba.TypePrefix) string
	db         *dynamo.DB
	table      string
}

func New(cfg Params) *DynamoStorage {
	db := dynamo.New(cfg.AWSSession, cfg.AWSConfig)

	return &DynamoStorage{
		db:         db,
		table:      cfg.TableName,
		generateID: cfg.IDGenerator,
	}
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
