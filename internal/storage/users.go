package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/guregu/dynamo"
)

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

func (s *DynamoStorage) ListUserEmails(ctx context.Context, userID string) (ems []*Email, err error) {
	allems := []*Email{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		AllWithContext(ctx, &allems)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListUserEmails: %w", err)
	}

	ems = []*Email{}
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
