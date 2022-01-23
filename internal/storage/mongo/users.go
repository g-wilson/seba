package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *MongoStorage) GetUserByID(ctx context.Context, userID string) (seba.User, error) {
	ent := User{}

	err := s.db.Collection(CollectionUsers).
		FindOne(ctx, bson.M{
			"_id": userID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return seba.User{}, seba.ErrUserNotFound
		}

		return seba.User{}, fmt.Errorf("mongo: GetUserByID: %w", err)
	}

	if ent.RemovedAt != nil {
		return seba.User{}, seba.ErrUserNotFound
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetUserByEmail(ctx context.Context, email string) (seba.User, error) {
	ent := User{}

	err := s.db.Collection(CollectionUsers).
		FindOne(ctx, bson.M{
			"emails.email": email,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return seba.User{}, seba.ErrUserNotFound
		}

		return seba.User{}, fmt.Errorf("mongo: GetUserByEmail: %w", err)
	}

	if ent.RemovedAt != nil {
		return seba.User{}, seba.ErrUserNotFound
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetUserExtended(ctx context.Context, userID string) (seba.UserExtended, error) {
	usr := User{}

	err := s.db.Collection(CollectionUsers).
		FindOne(ctx, bson.M{
			"_id": userID,
		}).
		Decode(&usr)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return seba.UserExtended{}, seba.ErrUserNotFound
		}

		return seba.UserExtended{}, fmt.Errorf("mongo: GetUserByIDExtended: %w", err)
	}

	extendedUser := seba.UserExtended{
		ID:        userID,
		CreatedAt: usr.CreatedAt,
		RemovedAt: usr.RemovedAt,
		Emails:    []seba.Email{},
	}

	for _, em := range usr.Emails {
		extendedUser.Emails = append(extendedUser.Emails, em.ToApp(userID))
	}

	storedCreds, err := s.ListUserWebauthnCredentials(ctx, userID)
	if err != nil {
		return seba.UserExtended{}, fmt.Errorf("mongo: GetUserExtended: %w", err)
	}

	extendedUser.SecondFactorEnrolled = len(storedCreds) > 0

	return extendedUser, nil
}

func (s *MongoStorage) CreateUserWithEmail(ctx context.Context, emailAddress string) (seba.User, error) {
	timestamp := time.Now().UTC()
	userID := generateID(TypePrefixUser)
	emailID := generateID(TypePrefixEmail)

	ent := User{
		ID:        userID,
		CreatedAt: timestamp,
		Emails: []UserEmail{
			{
				ID:        emailID,
				Email:     emailAddress,
				CreatedAt: timestamp,
			},
		},
	}

	_, err := s.db.Collection(CollectionUsers).
		InsertOne(ctx, ent)
	if err != nil {
		if isDuplicateKeyException(err) {
			return seba.User{}, seba.ErrEmailTaken
		}

		return seba.User{}, fmt.Errorf("mongo: CreateUserWithEmail: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) ListUserEmails(ctx context.Context, userID string) (ems []seba.Email, err error) {
	ent := User{}

	err = s.db.Collection(CollectionUsers).
		FindOne(ctx, bson.M{
			"_id": userID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, seba.ErrUserNotFound
		}

		return nil, fmt.Errorf("mongo: ListUserEmails: %w", err)
	}

	if ent.RemovedAt != nil {
		return nil, seba.ErrUserNotFound
	}

	ems = []seba.Email{}
	for _, em := range ent.Emails {
		if em.RemovedAt == nil {
			ems = append(ems, em.ToApp(ent.ID))
		}
	}

	return
}
