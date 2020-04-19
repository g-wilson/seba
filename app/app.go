package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/g-wilson/seba/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/runtime/logger"
	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	InviteCallbackURL = "https://localhost:8080/invite"
)

// App holds dependencies and has methods implementing business logic
type App struct {
	Logger  *logrus.Entry
	Storage storage.Storage

	jwtConfig          *JWTConfig
	actuallySendEmails bool
	ses                *ses.SES
}

type JWTConfig struct {
	Issuer string
	Signer jose.Signer
}

func New() (*App, error) {
	appLogger := logger.Create("seba", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	jwtConfig, err := createJWTConfig(os.Getenv("SEBA_PRIVATE_KEY"), os.Getenv("SEBA_ISSUER"))
	if err != nil {
		return nil, err
	}

	app := &App{
		Logger:  appLogger,
		Storage: storage.NewDynamoStorage(awsSession, awsConfig, os.Getenv("SEBA_DYNAMO_TABLE_NAME")),

		jwtConfig:          jwtConfig,
		ses:                ses.New(awsSession),
		actuallySendEmails: (os.Getenv("ACTUALLY_SEND_EMAILS") == "true"),
	}

	return app, nil
}

func createJWTConfig(keyStr, issuer string) (*JWTConfig, error) {
	key := jose.JSONWebKey{}
	err := key.UnmarshalJSON([]byte(keyStr))
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}
	if !key.Valid() {
		return nil, errors.New("key invalid")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		return nil, err
	}
	return &JWTConfig{
		Issuer: issuer,
		Signer: signer,
	}, nil
}

func init() {
	assertAvailablePRNG()
}
