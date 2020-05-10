package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/g-wilson/runtime/hand"
	"github.com/guregu/dynamo"
)

type DynamoStorage struct {
	db    *dynamo.DB
	table string
}

func NewDynamoStorage(awsSession *session.Session, awsConfig *aws.Config, tableName string) *DynamoStorage {
	db := dynamo.New(awsSession, awsConfig)
	return &DynamoStorage{db: db, table: tableName}
}

func (s *DynamoStorage) Setup() error {
	schema := struct {
		ID          string `dynamo:"id,hash"`
		Relation    string `dynamo:"relation,range" index:"relationLookup,hash"`
		LookupValue string `dynamo:"lookup_value" index:"valueLookup,hash"`
	}{}

	err := s.db.CreateTable(s.table, schema).OnDemand(true).Run()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ResourceInUseException" {
				return nil
			}
		}

		return err
	}

	return nil
}

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

	return
}

func (s *DynamoStorage) GetAuthenticationByID(ctx context.Context, authenticationID string) (ent *Authentication, err error) {
	ent = &Authentication{}

	err = s.db.Table(s.table).
		Get("id", authenticationID).
		OneWithContext(ctx, ent)

	if err != nil {
		if err == dynamo.ErrNotFound {
			err = hand.New("authentication_not_found")
		}
	}

	return
}

func (s *DynamoStorage) GetAuthenticationByHashedCode(ctx context.Context, hashedCode string) (ent *Authentication, err error) {
	ent = &Authentication{}

	err = s.db.Table(s.table).
		Get("lookup_value", hashedCode).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		OneWithContext(ctx, ent)

	if err != nil {
		if err == dynamo.ErrNotFound {
			err = hand.New("authentication_not_found")
		}

		return
	}
	if ent.RevokedAt != nil {
		return nil, hand.New("authentication_not_found")
	}

	return
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
			err = hand.New("authentication_already_verified")
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

	return
}

func (s *DynamoStorage) ListPendingAuthentications(ctx context.Context, email string) (authns []Authentication, err error) {
	authns = []Authentication{}

	err = s.db.Table(s.table).
		Get("relation", email).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixAuthentication).
		Filter("attribute_not_exists(verified_at)").
		Filter("attribute_not_exists(revoked_at)").
		AllWithContext(ctx, &authns)

	return
}

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
			err = hand.New("refresh_token_not_found")
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
			err = hand.New("refresh_token_already_used")
		}
	}

	return
}

func (s *DynamoStorage) GetAccountByID(ctx context.Context, accountID string) (ent *Account, err error) {
	ent = &Account{}

	err = s.db.Table(s.table).
		Get("id", accountID).
		Range("relation", dynamo.Equal, accountID).
		OneWithContext(ctx, ent)

	if err != nil {
		if err == dynamo.ErrNotFound {
			err = hand.New("account_not_found")
		}
	}
	if ent.RemovedAt != nil {
		err = hand.New("account_not_found")
	}

	return
}

func (s *DynamoStorage) ListUsersByAccountID(ctx context.Context, accountID string) (res []User, err error) {
	usrs := []User{}
	res = []User{}

	err = s.db.Table(s.table).
		Get("relation", accountID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixUser).
		AllWithContext(ctx, &usrs)

	for _, usr := range usrs {
		if usr.RemovedAt == nil {
			res = append(res, usr)
		}
	}

	return
}

func (s *DynamoStorage) GetUserByID(ctx context.Context, userID string) (ent *User, err error) {
	ent = &User{}

	err = s.db.Table(s.table).
		Get("id", userID).
		Range("relation", dynamo.BeginsWith, TypePrefixAccount).
		OneWithContext(ctx, ent)

	if err != nil {
		if err == dynamo.ErrNotFound {
			err = hand.New("user_not_found")
		}
	}
	if ent.RemovedAt != nil {
		err = hand.New("user_not_found")
	}

	return
}

func (s *DynamoStorage) GetUserByEmail(ctx context.Context, email string) (ent *User, err error) {
	emailEnt := &Email{}
	ent = &User{}

	err = s.db.Table(s.table).
		Get("lookup_value", email).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		OneWithContext(ctx, emailEnt)

	if err != nil {
		if err == dynamo.ErrNotFound {
			err = hand.New("user_not_found")
		}

		return
	}

	err = s.db.Table(s.table).
		Get("id", emailEnt.UserID).
		Range("relation", dynamo.BeginsWith, TypePrefixAccount).
		OneWithContext(ctx, ent)

	if err != nil && err == dynamo.ErrNotFound {
		err = hand.New("user_not_found")
	}
	if ent.RemovedAt != nil {
		err = hand.New("user_not_found")
	}

	return
}

func (s *DynamoStorage) CreateAccount(ctx context.Context) (ent *Account, err error) {
	timestamp := time.Now().UTC()

	ent = &Account{
		ID:        generateID(TypePrefixAccount),
		CreatedAt: timestamp,
	}

	ent.Relation = ent.ID

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)

	return
}

func (s *DynamoStorage) CreateUserWithEmail(ctx context.Context, accountID, emailAddress string) (user *User, err error) {
	timestamp := time.Now().UTC()

	user = &User{
		ID:        generateID(TypePrefixUser),
		CreatedAt: timestamp,
		AccountID: accountID,
	}

	email := &Email{
		ID:        generateID(TypePrefixEmail),
		Email:     emailAddress,
		CreatedAt: timestamp,
		UserID:    user.ID,
	}

	// hash the email to prevent PII
	emailDedupeValue := fmt.Sprintf("emaildedupe_%s", sha256Hex(emailAddress))

	dedupeRecord := struct {
		Hash  string `dynamo:"id"`
		Range string `dynamo:"relation"`
	}{
		Hash:  emailDedupeValue,
		Range: "email_dedupe_global",
	}

	tx := s.db.WriteTx().Idempotent(true)
	tbl := s.db.Table(s.table)

	tx.
		Put(tbl.Put(user)).
		Put(tbl.Put(email)).
		Put(tbl.Put(dedupeRecord).If("attribute_not_exists(id)"))

	err = tx.RunWithContext(ctx)

	if err != nil {
		if aErr, ok := err.(awserr.Error); ok {
			if strings.Contains(aErr.Error(), "ConditionalCheckFailed") {
				err = hand.New("email_taken")
			}
		}
	}

	return
}

func (s *DynamoStorage) CreateInvite(ctx context.Context, accountID, email, token string) (ent *Invite, err error) {
	timestamp := time.Now().UTC()

	ent = &Invite{
		ID:        generateID(TypePrefixInvite),
		CreatedAt: timestamp,
		Token:     token,
		AccountID: accountID,
		Email:     email,
	}

	err = s.db.Table(s.table).
		Put(ent).
		RunWithContext(ctx)

	return
}

func (s *DynamoStorage) GetInviteByHashedToken(ctx context.Context, token string) (ent *Invite, err error) {
	ent = &Invite{}

	err = s.db.Table(s.table).
		Get("lookup_value", token).
		Index("valueLookup").
		Range("id", dynamo.BeginsWith, TypePrefixInvite).
		OneWithContext(ctx, ent)

	if err != nil && err == dynamo.ErrNotFound {
		err = hand.New("invite_not_found")
	}

	return
}

func (s *DynamoStorage) SetInviteUsed(ctx context.Context, inviteID, accountID string) (err error) {
	timestamp := time.Now().UTC()

	err = s.db.Table(s.table).
		Update("id", inviteID).
		Range("relation", accountID).
		If("attribute_not_exists(consumed_at)").
		Set("consumed_at", timestamp.Unix()).
		RunWithContext(ctx)

	if err != nil && strings.HasPrefix(err.Error(), dynamodb.ErrCodeConditionalCheckFailedException) {
		err = hand.New("invite_already_consumed")
	}

	return
}

func (s *DynamoStorage) GetUserEmails(ctx context.Context, userID string) (ems []Email, err error) {
	ems = []Email{}

	err = s.db.Table(s.table).
		Get("relation", userID).
		Index("relationLookup").
		Range("id", dynamo.BeginsWith, TypePrefixEmail).
		AllWithContext(ctx, &ems)

	return
}

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
