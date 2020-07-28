package storage

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
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
		ID          string `dynamo:"id,hash"` // TODO: there is no way to set this as the range key for both of the other GSIs so it has to be done manually
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

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}
