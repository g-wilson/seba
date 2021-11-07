package dynamo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/g-wilson/seba"

	"github.com/aws/aws-sdk-go/aws/awserr"
)

func (s *DynamoStorage) CreateGoogleVerification(ctx context.Context, nonce, iss, aud, sub string) (seba.GoogleVerification, error) {
	timestamp := time.Now().UTC()

	ent := GoogleVerification{
		ID:        generateID(TypePrefixGoogleVerification),
		CreatedAt: timestamp,
		Nonce:     nonce,
		Issuser:   iss,
		Audience:  aud,
		Subject:   sub,
	}

	dedupeRecord := struct {
		Hash  string `dynamo:"id"`
		Range string `dynamo:"relation"`
	}{
		Hash:  createGoogleNonceDedupeID(nonce),
		Range: "google_nonce_dedupe_global",
	}

	tx := s.db.WriteTx().Idempotent(true)
	tbl := s.db.Table(s.table)

	tx.
		Put(tbl.Put(ent)).
		Put(tbl.Put(dedupeRecord).If("attribute_not_exists(id)"))

	err := tx.RunWithContext(ctx)
	if err != nil {
		if aErr, ok := err.(awserr.Error); ok {
			if strings.Contains(aErr.Error(), "ConditionalCheckFailed") {
				return seba.GoogleVerification{}, seba.ErrGoogleAlreadyVerified
			}
		}

		return seba.GoogleVerification{}, fmt.Errorf("dynamo: CreateUserWithEmail: %w", err)
	}

	return ent.ToApp(), nil
}

func createGoogleNonceDedupeID(nonce string) string {
	hash := sha256.New()
	hash.Write([]byte(nonce))

	digest := hex.EncodeToString(hash.Sum(nil))

	return fmt.Sprintf("googlenoncededupe_%s", digest)
}
