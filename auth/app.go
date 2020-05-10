package auth

import (
	"errors"
	"fmt"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/runtime/logger"
	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
)

// Config type is used as the argument to the app constructor
type Config struct {
	LogLevel  string
	LogFormat string

	AWSConfig       *aws.Config
	AWSSession      *session.Session
	DynamoTableName string

	ActuallySendEmails bool

	JWTPrivateKey string
	JWTIssuer     string

	Clients []seba.Client
}

// App holds dependencies and has methods implementing business logic
type App struct {
	Logger  *logrus.Entry
	Storage storage.Storage

	jwtConfig          *jwtConfig
	actuallySendEmails bool
	ses                *ses.SES

	clients     []seba.Client
	clientsByID map[string]seba.Client
}

type jwtConfig struct {
	Issuer string
	Signer jose.Signer
}

// New creates a new SEBA auth service app instance
func New(cfg Config) (*App, error) {
	appLogger := logger.Create("seba-auth", cfg.LogFormat, cfg.LogLevel)

	jwtConfig, err := createJWTConfig(cfg.JWTPrivateKey, cfg.JWTIssuer)
	if err != nil {
		return nil, err
	}

	app := &App{
		Logger:  appLogger,
		Storage: storage.NewDynamoStorage(cfg.AWSSession, cfg.AWSConfig, cfg.DynamoTableName),

		jwtConfig:          jwtConfig,
		ses:                ses.New(cfg.AWSSession),
		actuallySendEmails: cfg.ActuallySendEmails,

		clients:     cfg.Clients,
		clientsByID: arrangeClients(cfg.Clients),
	}

	return app, nil
}

func createJWTConfig(keyStr, issuer string) (*jwtConfig, error) {
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
	return &jwtConfig{
		Issuer: issuer,
		Signer: signer,
	}, nil
}

func arrangeClients(list []seba.Client) map[string]seba.Client {
	arr := map[string]seba.Client{}

	for _, cl := range list {
		arr[cl.ID] = cl
	}

	return arr
}
