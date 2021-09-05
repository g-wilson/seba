package dynamo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
)

func (s *DynamoStorage) CreateAuthentication(ctx context.Context, hashedCode, email, challenge, clientID string) (seba.Authentication, error) {
	timestamp := time.Now().UTC()

	ent := Authentication{
		ID:            generateID(TypePrefixAuthentication),
		CreatedAt:     timestamp,
		HashedCode:    hashedCode,
		Email:         email,
		PKCEChallenge: challenge,
		ClientID:      clientID,
	}

	err := s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return seba.Authentication{}, fmt.Errorf("dynamo: CreateAuthentication: %w", err)
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) GetAuthenticationByID(ctx context.Context, authenticationID string) (seba.Authentication, error) {
	ent := Authentication{}

	err := s.db.Table(s.table).
		Get("id", authenticationID).
		Range("relation", dynamo.BeginsWith, TypePrefixAuthentication).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrAuthnNotFound
		} else {
			err = fmt.Errorf("dynamo: GetAuthenticationByID: %w", err)
		}

		return seba.Authentication{}, err
	}

	return ent.ToApp(), nil
}

func (s *DynamoStorage) GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (seba.Authentication, error) {
	ent := &Authentication{}

	err := s.db.Table(s.table).
		Get("lookup", hashedCode).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			return seba.Authentication{}, seba.ErrAuthnNotFound
		}

		return seba.Authentication{}, fmt.Errorf("dynamo: GetAuthenticationByHashedCode: %w", err)
	}

	if ent.RevokedAt != nil {
		return seba.Authentication{}, seba.ErrAuthnNotFound
	}

	return ent.ToApp(), nil
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

func (s *DynamoStorage) ListPendingAuthentications(ctx context.Context, email string) ([]seba.Authentication, error) {
	authns := []Authentication{}

	err := s.db.Table(s.table).
		Get("relation", email).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		Filter("attribute_not_exists(verified_at)").
		Filter("attribute_not_exists(revoked_at)").
		AllWithContext(ctx, &authns)
	if err != nil {
		return nil, fmt.Errorf("dynamo: ListPendingAuthentications: %w", err)
	}

	res := []seba.Authentication{}
	for _, an := range authns {
		res = append(res, an.ToApp())
	}

	return res, nil
}

func (s *DynamoStorage) RevokePendingAuthentications(ctx context.Context, email string) (err error) {
	authns, err := s.ListPendingAuthentications(ctx, email)
	if err != nil {
		return
	}

	for _, an := range authns {
		err = s.SetAuthenticationRevoked(ctx, an.ID, email)
		if err != nil {
			return
		}
	}

	return
}
