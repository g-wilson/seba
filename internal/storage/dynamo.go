package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
)

type DynamoStorage struct {
	db    *dynamo.DB
	table string
}

func NewDynamoStorage(awsSession *session.Session, awsConfig *aws.Config, tableName string) *DynamoStorage {
	db := dynamo.New(awsSession, awsConfig)
	return &DynamoStorage{db: db, table: tableName}
}

func (s *DynamoStorage) Setup() error {
	schema := struct {
		ID          string `dynamo:"id,hash"` // TODO: there is no way to set this as the range key for both of the other GSIs so it has to be done manually
		Relation    string `dynamo:"relation,range" index:"relationLookup,hash"`
		LookupValue string `dynamo:"lookup_value" index:"valueLookup,hash"`
	}{}

	err := s.db.CreateTable(s.table, schema).OnDemand(true).Run()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ResourceInUseException" {
				return nil
			}
		}

		return err
	}

	return nil
}

func (s *DynamoStorage) CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (ent *Authentication, err error) {
	timestamp := time.Now().UTC()

	ent = &Authentication{
		ID:            generateID(TypePrefixAuthentication),
		CreatedAt:     timestamp,
		HashedCode:    hashedCode,
		Email:         email,
		PKCEChallenge: challenge,
		ClientID:      clientID,
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateAuthentication: %w", err)
	}

	return
}

func (s *DynamoStorage) GetAuthenticationByID(ctx context.Context, authenticationID string) (ent *Authentication, err error) {
	ent = &Authentication{}

	err = s.db.Table(s.table).
		Get("id", authenticationID).
		Range("relation", dynamo.BeginsWith, TypePrefixAuthentication).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrAuthnNotFound
		} else {
			err = fmt.Errorf("dynamo: GetAuthenticationByID: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (*Authentication, error) {
	ent := &Authentication{}

	err := s.db.Table(s.table).
		Get("lookup_value", hashedCode).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return nil, seba.ErrAuthnNotFound
		}

		return nil, fmt.Errorf("dynamo: GetAuthenticationByHashedCode: %w", err)
	}

	if ent.RevokedAt != nil {
		return nil, seba.ErrAuthnNotFound
	}

	return ent, nil
}

func (s *DynamoStorage) SetAuthenticationVerified(ctx context.Context, authenticationID, email string) (err error) {
	timestamp := time.Now().UTC()

	err = s.db.Table(s.table).
		Update("id", authenticationID).
		Range("relation", email).
		If("attribute_not_exists(verified_at)").
		Set("verified_at", timestamp.Unix()).
		RunWithContext(ctx)
	if err != nil {
		if strings.HasPrefix(err.Error(), dynamodb.ErrCodeConditionalCheckFailedException) {
			err = seba.ErrAuthnAlreadyVerified
		} else {
			err = fmt.Errorf("dynamo: SetAuthenticationVerified: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) SetAuthenticationRevoked(ctx context.Context, authenticationID, email string) (err error) {
	timestamp := time.Now().UTC()

	err = s.db.Table(s.table).
		Update("id", authenticationID).
		Range("relation", email).
		Set("revoked_at", timestamp.Unix()).
		RunWithContext(ctx)
	if err != nil {
		return fmt.Errorf("dynamo: SetAuthenticationRevoked: %w", err)
	}

	return
}

func (s *DynamoStorage) ListPendingAuthentications(ctx context.Context, email string) (authns []Authentication, err error) {
	authns = []Authentication{}

	err = s.db.Table(s.table).
		Get("relation", email).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		Filter("attribute_not_exists(verified_at)").
		Filter("attribute_not_exists(revoked_at)").
		AllWithContext(ctx, &authns)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListPendingAuthentications: %w", err)
	}

	return
}

func (s *DynamoStorage) CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (ent *RefreshToken, err error) {
	timestamp := time.Now().UTC()

	ent = &RefreshToken{
		ID:          generateID(TypePrefixRefreshToken),
		CreatedAt:   timestamp,
		UserID:      userID,
		ClientID:    clientID,
		HashedToken: hashedToken,
	}

	if authnID != nil {
		ent.AuthenticationID = authnID
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateRefreshToken: %w", err)
	}

	return
}

func (s *DynamoStorage) GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (ent *RefreshToken, err error) {
	ent = &RefreshToken{}

	err = s.db.Table(s.table).
		Get("lookup_value", hashedToken).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixRefreshToken).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrRefreshTokenNotFound
		} else {
			err = fmt.Errorf("dynamo: GetRefreshTokenByHashedToken: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) (err error) {
	timestamp := time.Now().UTC()

	err = s.db.Table(s.table).
		Update("id", reftokID).
		Range("relation", userID).
		If("attribute_not_exists(used_at)").
		Set("used_at", timestamp.Unix()).
		RunWithContext(ctx)
	if err != nil {
		if strings.HasPrefix(err.Error(), dynamodb.ErrCodeConditionalCheckFailedException) {
			err = seba.ErrRefreshTokenUsed
		} else {
			err = fmt.Errorf("dynamo: SetRefreshTokenUsed: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) GetUserByID(ctx context.Context, userID string) (ent *User, err error) {
	ent = &User{}

	err = s.db.Table(s.table).
		Get("id", userID).
		Range("relation", dynamo.Equal, userID).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return nil, seba.ErrUserNotFound
		}

		return nil, fmt.Errorf("dynamo: GetUserByID: %w", err)
	}

	if ent.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	return ent, nil
}

func (s *DynamoStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	emailEnt := &Email{}
	ent := &User{}

	err := s.db.Table(s.table).
		Get("lookup_value", email).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		OneWithContext(ctx, emailEnt)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return nil, seba.ErrUserNotFound
		}

		return nil, fmt.Errorf("dynamo: GetUserByEmail: %w", err)
	}
	if emailEnt.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	err = s.db.Table(s.table).
		Get("id", emailEnt.UserID).
		Range("relation", dynamo.BeginsWith, TypePrefixUser).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return nil, seba.ErrUserNotFound
		}

		return nil, fmt.Errorf("dynamo: GetUserByEmail: %w", err)
	}

	if ent.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	return ent, nil
}

func (s *DynamoStorage) CreateUserWithEmail(ctx context.Context, emailAddress string) (*User, error) {
	timestamp := time.Now().UTC()
	userID := generateID(TypePrefixUser)

	user := &User{
		ID:        userID,
		CreatedAt: timestamp,
		Relation:  userID,
	}

	email := &Email{
		ID:        generateID(TypePrefixEmail),
		Email:     emailAddress,
		CreatedAt: timestamp,
		UserID:    user.ID,
	}

	dedupeRecord := struct {
		Hash  string `dynamo:"id"`
		Range string `dynamo:"relation"`
	}{
		Hash:  createEmailDedupeID(emailAddress),
		Range: "email_dedupe_global",
	}

	tx := s.db.WriteTx().Idempotent(true)
	tbl := s.db.Table(s.table)

	tx.
		Put(tbl.Put(user)).
		Put(tbl.Put(email)).
		Put(tbl.Put(dedupeRecord).If("attribute_not_exists(id)"))

	err := tx.RunWithContext(ctx)
	if err != nil {
		if aErr, ok := err.(awserr.Error); ok {
			if strings.Contains(aErr.Error(), "ConditionalCheckFailed") {
				return nil, seba.ErrEmailTaken
			}
		}

		return nil, fmt.Errorf("dynamo: CreateUserWithEmail: %w", err)
	}

	return user, nil
}

func (s *DynamoStorage) ListUserEmails(ctx context.Context, userID string) (ems []Email, err error) {
	allems := []Email{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		AllWithContext(ctx, &allems)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListUserEmails: %w", err)
	}

	ems = []Email{}
	for _, em := range allems {
		if em.RemovedAt == nil {
			ems = append(ems, em)
		}
	}

	return
}

func createEmailDedupeID(email string) string {
	return fmt.Sprintf("emaildedupe_%s", sha256Hex(email))
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
