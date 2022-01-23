package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *MongoStorage) CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken, grantID string) (seba.RefreshToken, error) {
	timestamp := time.Now().UTC()

	ent := RefreshToken{
		ID:          generateID(TypePrefixRefreshToken),
		CreatedAt:   timestamp,
		UserID:      userID,
		ClientID:    clientID,
		HashedToken: hashedToken,
		GrantID:     grantID,
	}

	_, err := s.db.Collection(CollectionRefreshTokens).
		InsertOne(ctx, ent)
	if err != nil {
		return seba.RefreshToken{}, fmt.Errorf("mongo: CreateRefreshToken: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetRefreshTokenByID(ctx context.Context, reftokID string) (seba.RefreshToken, error) {
	ent := RefreshToken{}

	err := s.db.Collection(CollectionRefreshTokens).
		FindOne(ctx, bson.M{
			"_id": reftokID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = seba.ErrRefreshTokenNotFound
		} else {
			err = fmt.Errorf("mongo: GetRefreshTokenByID: %w", err)
		}

		return seba.RefreshToken{}, err
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (seba.RefreshToken, error) {
	ent := RefreshToken{}

	err := s.db.Collection(CollectionRefreshTokens).
		FindOne(ctx, bson.M{
			"hashed_token": hashedToken,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = seba.ErrRefreshTokenNotFound
		} else {
			err = fmt.Errorf("mongo: GetRefreshTokenByHashedToken: %w", err)
		}

		return seba.RefreshToken{}, err
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) (err error) {
	timestamp := time.Now().UTC()

	_, err = s.db.Collection(CollectionRefreshTokens).
		UpdateOne(
			ctx,
			bson.M{
				"_id":     reftokID,
				"user_id": userID,
				"used_at": nil,
			},
			bson.M{"$set": bson.M{
				"used_at": timestamp,
			}},
		)
	if err != nil {
		if isDuplicateKeyException(err) {
			err = seba.ErrRefreshTokenUsed
		} else {
			err = fmt.Errorf("mongo: SetRefreshTokenUsed: %w", err)
		}
	}

	return
}
