package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"
)

func (s *MongoStorage) CreateGoogleVerification(ctx context.Context, nonce, iss, aud, sub string) (seba.GoogleVerification, error) {
	timestamp := time.Now().UTC()

	ent := GoogleVerification{
		ID:        generateID(TypePrefixGoogleVerification),
		CreatedAt: timestamp,
		Nonce:     nonce,
		Issuser:   iss,
		Audience:  aud,
		Subject:   sub,
	}

	_, err := s.db.Collection(CollectionGoogleVerifications).
		InsertOne(ctx, ent)
	if err != nil {
		if isDuplicateKeyException(err) {
			return seba.GoogleVerification{}, seba.ErrGoogleAlreadyVerified
		}

		return seba.GoogleVerification{}, fmt.Errorf("mongo: CreateGoogleVerification: %w", err)
	}

	return ent.ToApp(), nil
}
