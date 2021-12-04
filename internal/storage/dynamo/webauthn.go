package dynamo

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"

	"github.com/guregu/dynamo"
)

func (s *DynamoStorage) CreateWebauthnRegistrationChallenge(ctx context.Context, userID, sessionID, challenge string) (seba.WebauthnChallenge, error) {
	timestamp := time.Now().UTC()

	ent := WebauthnChallenge{
		ID:            generateID(TypePrefixWebauthnChallenge),
		CreatedAt:     timestamp,
		UserID:        userID,
		SessionID:     sessionID,
		Challenge:     challenge,
		ChallengeType: "register",
	}

	err := s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return seba.WebauthnChallenge{}, fmt.Errorf("dynamo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) CreateWebauthnVerificationChallenge(ctx context.Context, userID, sessionID, challenge string, credentialIDs []string) (seba.WebauthnChallenge, error) {
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

	err := s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return seba.WebauthnChallenge{}, fmt.Errorf("dynamo: CreateWebauthnVerificationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) GetWebauthnChallenge(ctx context.Context, challengeID string) (seba.WebauthnChallenge, error) {
	ent := WebauthnChallenge{}

	err := s.db.Table(s.table).
		Get("id", challengeID).
		Range("relation", dynamo.BeginsWith, TypePrefixWebauthnChallenge).
		OneWithContext(ctx, &ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrWebauthnChallengeNotFound
		} else {
			err = fmt.Errorf("dynamo: GetWebauthnChallenge: %w", err)
		}

		return seba.WebauthnChallenge{}, err
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) ListUserWebauthnCredentials(ctx context.Context, userID string) (creds []seba.WebauthnCredential, err error) {
	allcreds := []*WebauthnCredential{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixWebauthnCredential).
		AllWithContext(ctx, &allcreds)
	if err != nil {
		err = fmt.Errorf("dynamo: ListUserWebauthnCredentials: %w", err)
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

func (s *DynamoStorage) GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (seba.WebauthnCredential, error) {
	ent := WebauthnCredential{}

	err := s.db.Table(s.table).
		Get("lookup", credentialID).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixWebauthnCredential).
		OneWithContext(ctx, &ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrWebauthnCredentialNotFound
		} else {
			err = fmt.Errorf("dynamo: GetWebauthnCredentialByCredentialID: %w", err)
		}

		return seba.WebauthnCredential{}, err
	}
	if ent.RemovedAt != nil {
		return seba.WebauthnCredential{}, seba.ErrWebauthnCredentialNotFound
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType, credentialID, publicKey, AAGUID string, userVerified bool, signCount int) (seba.WebauthnCredential, error) {
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

	err := s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return seba.WebauthnCredential{}, fmt.Errorf("dynamo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) UpdateWebauthnCredential(ctx context.Context, userID, credentialID string, signCount int) error {
	err := s.db.Table(s.table).
		Update("id", credentialID).
		Range("relation", userID).
		Set("sign_count", signCount).
		RunWithContext(ctx)
	if err != nil {
		return fmt.Errorf("dynamo: UpdateWebauthnCredential: %w", err)
	}

	return nil
}
