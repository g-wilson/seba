package dynamo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/guregu/dynamo"
	"golang.org/x/sync/errgroup"
)

func (s *DynamoStorage) GetUserByID(ctx context.Context, userID string) (seba.User, error) {
	ent := User{}

	err := s.db.Table(s.table).
		Get("id", userID).
		Range("relation", dynamo.Equal, userID).
		OneWithContext(ctx, &ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return seba.User{}, seba.ErrUserNotFound
		}

		return seba.User{}, fmt.Errorf("dynamo: GetUserByID: %w", err)
	}

	if ent.RemovedAt != nil {
		return seba.User{}, seba.ErrUserNotFound
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) GetUserByEmail(ctx context.Context, email string) (seba.User, error) {
	emailEnt := Email{}
	ent := User{}

	err := s.db.Table(s.table).
		Get("lookup", email).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		OneWithContext(ctx, &emailEnt)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return seba.User{}, seba.ErrUserNotFound
		}

		return seba.User{}, fmt.Errorf("dynamo: GetUserByEmail: %w", err)
	}
	if emailEnt.RemovedAt != nil {
		return seba.User{}, seba.ErrUserNotFound
	}

	err = s.db.Table(s.table).
		Get("id", emailEnt.UserID).
		Range("relation", dynamo.BeginsWith, TypePrefixUser).
		OneWithContext(ctx, &ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return seba.User{}, seba.ErrUserNotFound
		}

		return seba.User{}, fmt.Errorf("dynamo: GetUserByEmail: %w", err)
	}

	if ent.RemovedAt != nil {
		return seba.User{}, seba.ErrUserNotFound
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) GetUserExtended(ctx context.Context, userID string) (seba.UserExtended, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return seba.UserExtended{}, err
	}

	extendedUser := seba.UserExtended{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		RemovedAt: user.RemovedAt,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		emails, err := s.ListUserEmails(gctx, user.ID)
		if err != nil {
			return err
		}

		extendedUser.Emails = emails

		return nil
	})

	g.Go(func() error {
		storedCreds, err := s.ListUserWebauthnCredentials(gctx, user.ID)
		if err != nil {
			return err
		}

		extendedUser.SecondFactorEnrolled = len(storedCreds) > 0

		return nil
	})

	err = g.Wait()
	if err != nil {
		return seba.UserExtended{}, fmt.Errorf("dynamo: GetUserExtended: %w", err)
	}

	return extendedUser, nil
}

func (s *DynamoStorage) CreateUserWithEmail(ctx context.Context, emailAddress string) (seba.User, error) {
	timestamp := time.Now().UTC()
	userID := generateID(TypePrefixUser)

	user := User{
		ID:        userID,
		CreatedAt: timestamp,
		Relation:  userID,
	}

	email := Email{
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
				return seba.User{}, seba.ErrEmailTaken
			}
		}

		return seba.User{}, fmt.Errorf("dynamo: CreateUserWithEmail: %w", err)
	}

	return user.ToApp(), nil
}

func (s *DynamoStorage) ListUserEmails(ctx context.Context, userID string) (ems []seba.Email, err error) {
	allems := []Email{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		AllWithContext(ctx, &allems)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListUserEmails: %w", err)
	}

	ems = []seba.Email{}
	for _, em := range allems {
		if em.RemovedAt == nil {
			ems = append(ems, em.ToApp())
		}
	}

	return
}

func createEmailDedupeID(email string) string {
	hash := sha256.New()
	hash.Write([]byte(email))

	digest := hex.EncodeToString(hash.Sum(nil))

	return fmt.Sprintf("emaildedupe_%s", digest)
}
