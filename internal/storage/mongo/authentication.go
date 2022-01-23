package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *MongoStorage) CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (seba.Authentication, error) {
	timestamp := time.Now().UTC()

	ent := Authentication{
		ID:            generateID(TypePrefixAuthentication),
		CreatedAt:     timestamp,
		HashedCode:    hashedCode,
		Email:         email,
		PKCEChallenge: challenge,
		ClientID:      clientID,
	}

	_, err := s.db.Collection(CollectionAuthentications).
		InsertOne(ctx, ent)
	if err != nil {
		return seba.Authentication{}, fmt.Errorf("mongo: CreateAuthentication: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetAuthenticationByID(ctx context.Context, authenticationID string) (seba.Authentication, error) {
	ent := Authentication{}

	err := s.db.Collection(CollectionAuthentications).
		FindOne(ctx, bson.M{
			"_id": authenticationID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = seba.ErrAuthnNotFound
		} else {
			err = fmt.Errorf("mongo: GetAuthenticationByID: %w", err)
		}

		return seba.Authentication{}, err
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (seba.Authentication, error) {
	ent := &Authentication{}

	err := s.db.Collection(CollectionAuthentications).
		FindOne(ctx, bson.M{
			"hashed_code": hashedCode,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return seba.Authentication{}, seba.ErrAuthnNotFound
		}

		return seba.Authentication{}, fmt.Errorf("mongo: GetAuthenticationByHashedCode: %w", err)
	}

	if ent.RevokedAt != nil {
		return seba.Authentication{}, seba.ErrAuthnNotFound
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) SetAuthenticationVerified(ctx context.Context, authenticationID, email string) (err error) {
	timestamp := time.Now().UTC()

	_, err = s.db.Collection(CollectionAuthentications).
		UpdateOne(
			ctx,
			bson.M{
				"_id":         authenticationID,
				"email":       email,
				"verified_at": nil,
			},
			bson.M{"$set": bson.M{
				"verified_at": timestamp,
			}},
		)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return seba.ErrAuthnNotFound
		}
		err = fmt.Errorf("mongo: SetAuthenticationVerified: %w", err)
	}

	return
}

func (s *MongoStorage) RevokePendingAuthentications(ctx context.Context, email string) (err error) {
	timestamp := time.Now().UTC()

	_, err = s.db.Collection(CollectionAuthentications).
		UpdateMany(
			ctx,
			bson.M{
				"email":       email,
				"verified_at": nil,
				"revoked_at":  nil,
			},
			bson.M{"$set": bson.M{
				"revoked_at": timestamp,
			}},
		)

	return
}
