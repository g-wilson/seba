package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *MongoStorage) CreateWebauthnRegistrationChallenge(ctx context.Context, userID, sessionID, challenge string) (seba.WebauthnChallenge, error) {
	timestamp := time.Now().UTC()

	ent := WebauthnChallenge{
		ID:            generateID(TypePrefixWebauthnChallenge),
		CreatedAt:     timestamp,
		UserID:        userID,
		SessionID:     sessionID,
		Challenge:     challenge,
		ChallengeType: "register",
	}

	_, err := s.db.Collection(CollectionWebauthnChallenges).
		InsertOne(ctx, ent)
	if err != nil {
		return seba.WebauthnChallenge{}, fmt.Errorf("mongo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) CreateWebauthnVerificationChallenge(ctx context.Context, userID, sessionID, challenge string, credentialIDs []string) (seba.WebauthnChallenge, error) {
	timestamp := time.Now().UTC()

	ent := WebauthnChallenge{
		ID:            generateID(TypePrefixWebauthnChallenge),
		CreatedAt:     timestamp,
		UserID:        userID,
		SessionID:     sessionID,
		Challenge:     challenge,
		ChallengeType: "verify",
		CredentialIDs: credentialIDs,
	}

	_, err := s.db.Collection(CollectionWebauthnChallenges).
		InsertOne(ctx, ent)
	if err != nil {
		return seba.WebauthnChallenge{}, fmt.Errorf("mongo: CreateWebauthnVerificationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) GetWebauthnChallenge(ctx context.Context, challengeID string) (seba.WebauthnChallenge, error) {
	ent := WebauthnChallenge{}

	err := s.db.Collection(CollectionWebauthnChallenges).
		FindOne(ctx, bson.M{
			"_id": challengeID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = seba.ErrWebauthnChallengeNotFound
		} else {
			err = fmt.Errorf("mongo: GetWebauthnChallenge: %w", err)
		}

		return seba.WebauthnChallenge{}, err
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) ListUserWebauthnCredentials(ctx context.Context, userID string) (creds []seba.WebauthnCredential, err error) {
	allcreds := []*WebauthnCredential{}

	cursor, err := s.db.Collection(CollectionWebauthnCredentials).
		Find(ctx, bson.M{
			"user_id": userID,
		})
	if err != nil {
		err = fmt.Errorf("mongo: ListUserWebauthnCredentials: %w", err)
		return
	}

	err = cursor.All(ctx, &allcreds)
	if err != nil {
		err = fmt.Errorf("mongo: ListUserWebauthnCredentials: %w", err)
		return
	}

	creds = []seba.WebauthnCredential{}
	for _, c := range allcreds {
		if c.RemovedAt == nil {
			creds = append(creds, c.ToApp())
		}
	}

	return
}

func (s *MongoStorage) GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (seba.WebauthnCredential, error) {
	ent := WebauthnCredential{}

	err := s.db.Collection(CollectionWebauthnCredentials).
		FindOne(ctx, bson.M{
			"_id": credentialID,
		}).
		Decode(&ent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = seba.ErrWebauthnCredentialNotFound
		} else {
			err = fmt.Errorf("mongo: GetWebauthnCredentialByCredentialID: %w", err)
		}

		return seba.WebauthnCredential{}, err
	}
	if ent.RemovedAt != nil {
		return seba.WebauthnCredential{}, seba.ErrWebauthnCredentialNotFound
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType, credentialID, publicKey, AAGUID string, userVerified bool, signCount int) (seba.WebauthnCredential, error) {
	timestamp := time.Now().UTC()

	ent := WebauthnCredential{
		ID:              generateID(TypePrefixWebauthnCredential),
		UserID:          userID,
		CreatedAt:       timestamp,
		Name:            name,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		AAGUID:          AAGUID,
		UserVerified:    userVerified,
		SignCount:       signCount,
	}

	_, err := s.db.Collection(CollectionWebauthnCredentials).
		InsertOne(ctx, ent)
	if err != nil {
		return seba.WebauthnCredential{}, fmt.Errorf("mongo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *MongoStorage) UpdateWebauthnCredential(ctx context.Context, userID, credentialID string, signCount int) error {
	_, err := s.db.Collection(CollectionWebauthnCredentials).
		UpdateOne(
			ctx,
			bson.M{
				"_id":     credentialID,
				"user_id": userID,
			},
			bson.M{"$set": bson.M{
				"sign_count": signCount,
			}},
		)
	if err != nil {
		return fmt.Errorf("mongo: UpdateWebauthnCredential: %w", err)
	}

	return nil
}
