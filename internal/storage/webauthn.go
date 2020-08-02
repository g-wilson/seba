package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/g-wilson/seba"
	"github.com/guregu/dynamo"
)

func (s *DynamoStorage) CreateWebauthnRegistrationChallenge(ctx context.Context, sessionID, challenge string) (ent *WebauthnChallenge, err error) {
	timestamp := time.Now().UTC()

	ent = &WebauthnChallenge{
		ID:            generateID(TypePrefixWebauthnChallenge),
		CreatedAt:     timestamp,
		SessionID:     sessionID,
		Challenge:     challenge,
		ChallengeType: "register",
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return
}

func (s *DynamoStorage) CreateWebauthnVerificationChallenge(ctx context.Context, sessionID, challenge string, credentialIDs []string) (ent *WebauthnChallenge, err error) {
	timestamp := time.Now().UTC()

	ent = &WebauthnChallenge{
		ID:            generateID(TypePrefixWebauthnChallenge),
		CreatedAt:     timestamp,
		SessionID:     sessionID,
		Challenge:     challenge,
		ChallengeType: "verify",
		CredentialIDs: credentialIDs,
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateWebauthnVerificationChallenge: %w", err)
	}

	return
}

func (s *DynamoStorage) GetWebauthnChallenge(ctx context.Context, challengeID string) (ent *WebauthnChallenge, err error) {
	ent = &WebauthnChallenge{}

	err = s.db.Table(s.table).
		Get("id", challengeID).
		Range("relation", dynamo.BeginsWith, TypePrefixRefreshToken).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrWebauthnChallengeNotFound
		} else {
			err = fmt.Errorf("dynamo: GetWebauthnChallenge: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) ListUserWebauthnCredentials(ctx context.Context, userID string) (creds []*WebauthnCredential, err error) {
	allcreds := []*WebauthnCredential{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixWebauthnCredential).
		AllWithContext(ctx, &allcreds)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListUserWebauthnCredentials: %w", err)
	}

	creds = []*WebauthnCredential{}
	for _, c := range allcreds {
		if c.RemovedAt == nil {
			creds = append(creds, c)
		}
	}

	return
}

func (s *DynamoStorage) GetWebauthnCredentialByCredentialID(ctx context.Context, credentialID string) (ent *WebauthnCredential, err error) {
	ent = &WebauthnCredential{}

	err = s.db.Table(s.table).
		Get("lookup_value", credentialID).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixWebauthnCredential).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrWebauthnCredentialNotFound
		} else {
			err = fmt.Errorf("dynamo: GetWebauthnCredentialByCredentialID: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) CreateWebAuthnCredential(ctx context.Context, userID, name, attestationType, credentialID, publicKey, AAGUID string, signCount int) (ent *WebauthnCredential, err error) {
	timestamp := time.Now().UTC()

	ent = &WebauthnCredential{
		ID:              generateID(TypePrefixWebauthnCredential),
		UserID:          userID,
		CreatedAt:       timestamp,
		Name:            name,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		AAGUID:          AAGUID,
		SignCount:       signCount,
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateWebauthnRegistrationChallenge: %w", err)
	}

	return
}

func (s *DynamoStorage) UpdateWebauthnCredential(ctx context.Context, userID, credentialID string, signCount int) (err error) {
	err = s.db.Table(s.table).
		Update("id", credentialID).
		Range("relation", userID).
		Set("sign_count", signCount).
		RunWithContext(ctx)
	if err != nil {
		return fmt.Errorf("dynamo: UpdateWebauthnCredential: %w", err)
	}

	return
}
