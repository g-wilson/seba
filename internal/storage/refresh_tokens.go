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

func (s *DynamoStorage) CreateRefreshToken(ctx context.Context, userID, clientID, hashedToken string, authnID *string) (ent *RefreshToken, err error) {
	timestamp := time.Now().UTC()

	ent = &RefreshToken{
		ID:          generateID(TypePrefixRefreshToken),
		CreatedAt:   timestamp,
		UserID:      userID,
		ClientID:    clientID,
		HashedToken: hashedToken,
	}

	if authnID != nil {
		ent.AuthenticationID = authnID
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamo: CreateRefreshToken: %w", err)
	}

	return
}

func (s *DynamoStorage) GetRefreshTokenByID(ctx context.Context, reftokID string) (ent *RefreshToken, err error) {
	ent = &RefreshToken{}

	err = s.db.Table(s.table).
		Get("id", reftokID).
		Range("relation", dynamo.BeginsWith, TypePrefixUser).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrRefreshTokenNotFound
		} else {
			err = fmt.Errorf("dynamo: GetRefreshTokenByID: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) GetRefreshTokenByHashedToken(ctx context.Context, hashedToken string) (ent *RefreshToken, err error) {
	ent = &RefreshToken{}

	err = s.db.Table(s.table).
		Get("lookup_value", hashedToken).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixRefreshToken).
		OneWithContext(ctx, ent)
	if err != nil {
		if err == dynamo.ErrNotFound {
			err = seba.ErrRefreshTokenNotFound
		} else {
			err = fmt.Errorf("dynamo: GetRefreshTokenByHashedToken: %w", err)
		}
	}

	return
}

func (s *DynamoStorage) SetRefreshTokenUsed(ctx context.Context, reftokID, userID string) (err error) {
	timestamp := time.Now().UTC()

	err = s.db.Table(s.table).
		Update("id", reftokID).
		Range("relation", userID).
		If("attribute_not_exists(used_at)").
		Set("used_at", timestamp.Unix()).
		RunWithContext(ctx)
	if err != nil {
		if strings.HasPrefix(err.Error(), dynamodb.ErrCodeConditionalCheckFailedException) {
			err = seba.ErrRefreshTokenUsed
		} else {
			err = fmt.Errorf("dynamo: SetRefreshTokenUsed: %w", err)
		}
	}

	return
}
