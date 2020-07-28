package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
)

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

func (s *DynamoStorage) ListPendingAuthentications(ctx context.Context, email string) (authns []*Authentication, err error) {
	authns = []*Authentication{}

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
