package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"github.com/segmentio/ksuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

const (
	CollectionAuthentications     = "authentications"
	CollectionRefreshTokens       = "refresh_tokens"
	CollectionUsers               = "users"
	CollectionWebauthnChallenges  = "webauthn_challenges"
	CollectionWebauthnCredentials = "webauthn_credentials"
	CollectionGoogleVerifications = "google_verifications"
)

const (
	ErrorCodeDuplicateKey = 11000
)

// MongoStorage meets the seba.Storage interface
type MongoStorage struct {
	db *mongo.Database
}

func New(db *mongo.Database) *MongoStorage {
	return &MongoStorage{
		db: db,
	}
}

func (s *MongoStorage) Setup() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = s.db.Collection("authentications").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{"hashed_code", 1}}},
		{Keys: bson.D{{"email", 1}}},
		{Keys: bson.D{{"created_at", -1}}},
	})

	_, err = s.db.Collection("refresh_tokens").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{"hashed_token", 1}}},
		{Keys: bson.D{{"user_id", 1}}},
	})

	_, err = s.db.Collection("users").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{"emails.email", 1}},
			Options: options.Index().SetUnique(true),
		},
	})

	_, err = s.db.Collection("webauthn_challenges").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{"user_id", 1}}},
		{Keys: bson.D{{"created_at", -1}}},
	})

	_, err = s.db.Collection("webauthn_credentials").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{"user_id", 1}}},
		{Keys: bson.D{{"created_at", -1}}},
	})

	_, err = s.db.Collection("google_verifications").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{"nonce", 1}},
			Options: options.Index().SetUnique(true),
		},
	})

	return
}

func isDuplicateKeyException(err error) bool {
	mongoWriteErr, ok := err.(mongo.WriteException)

	return ok && mongoWriteErr.HasErrorCode(ErrorCodeDuplicateKey)
}

func generateID(t TypePrefix) string {
	return fmt.Sprintf("%s_%s", t, ksuid.New().String())
}

type Authentication struct {
	ID            string     `bson:"_id"`
	Email         string     `bson:"email"`
	HashedCode    string     `bson:"hashed_code"`
	CreatedAt     time.Time  `bson:"created_at"`
	VerifiedAt    *time.Time `bson:"verified_at"`
	RevokedAt     *time.Time `bson:"revoked_at"`
	ClientID      string     `bson:"client_id"`
	PKCEChallenge string     `bson:"pkce_challenge"`
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
	ID          string     `bson:"_id"`
	UserID      string     `bson:"user_id"`
	HashedToken string     `bson:"hashed_token"`
	CreatedAt   time.Time  `bson:"created_at"`
	UsedAt      *time.Time `bson:"used_at"`
	ClientID    string     `bson:"client_id"`
	GrantID     string     `bson:"grant_id"`
}

func (r RefreshToken) ToApp() seba.RefreshToken {
	return seba.RefreshToken{
		ID:          r.ID,
		UserID:      r.UserID,
		HashedToken: r.HashedToken,
		CreatedAt:   r.CreatedAt,
		UsedAt:      r.UsedAt,
		ClientID:    r.ClientID,
		GrantID:     r.GrantID,
	}
}

type User struct {
	ID        string      `bson:"_id"`
	CreatedAt time.Time   `bson:"created_at"`
	RemovedAt *time.Time  `bson:"removed_at"`
	Emails    []UserEmail `bson:"emails"`
}

func (u User) ToApp() seba.User {
	return seba.User{
		ID:        u.ID,
		CreatedAt: u.CreatedAt,
		RemovedAt: u.RemovedAt,
	}
}

type UserEmail struct {
	ID        string     `bson:"_id"`
	Email     string     `bson:"email"`
	CreatedAt time.Time  `bson:"created_at"`
	RemovedAt *time.Time `bson:"removed_at"`
}

func (e UserEmail) ToApp(userID string) seba.Email {
	return seba.Email{
		ID:        e.ID,
		Email:     e.Email,
		UserID:    userID,
		CreatedAt: e.CreatedAt,
		RemovedAt: e.RemovedAt,
	}
}

type WebauthnCredential struct {
	ID              string     `bson:"_id"`
	UserID          string     `bson:"user_id"`
	CreatedAt       time.Time  `bson:"created_at"`
	RemovedAt       *time.Time `bson:"removed_at"`
	Name            string     `bson:"name"`
	CredentialID    string     `bson:"credential_id"`
	PublicKey       string     `bson:"public_key"`
	AttestationType string     `bson:"attestation_type"`
	AAGUID          string     `bson:"aaguid"`
	UserVerified    bool       `bson:"user_verified"`
	SignCount       int        `bson:"sign_count"`
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
	ID            string    `bson:"_id"`
	UserID        string    `bson:"user_id"`
	SessionID     string    `bson:"session_id"`
	CreatedAt     time.Time `bson:"created_at"`
	ChallengeType string    `bson:"challenge_type"`
	Challenge     string    `bson:"challenge"`
	CredentialIDs []string  `bson:"credential_ids,set"`
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
	ID        string    `bson:"_id"`
	CreatedAt time.Time `bson:"created_at"`
	Nonce     string    `bson:"nonce"`
	Subject   string    `bson:"subject"`
	Issuser   string    `bson:"issuer"`
	Audience  string    `bson:"audience"`
}

func (c GoogleVerification) ToApp() seba.GoogleVerification {
	return seba.GoogleVerification{
		ID:        c.ID,
		CreatedAt: c.CreatedAt,
		Nonce:     c.Nonce,
		Subject:   c.Subject,
		Issuser:   c.Issuser,
		Audience:  c.Audience,
	}
}
