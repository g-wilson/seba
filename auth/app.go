package auth

import (
	"errors"
	"fmt"
	"html/template"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/runtime/logger"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
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
	EmailConfig        EmailConfig

	JWTPrivateKey string
	JWTIssuer     string

	Clients []seba.Client
}

// EmailConfig type is a group of settings for emails
type EmailConfig struct {
	DefaultReplyAddress string
	DefaultFromAddress  string

	AuthnEmailSubject  string
	AuthnEmailTemplate *template.Template
}

type jwtConfig struct {
	Issuer string
	Signer jose.Signer
}

// App holds dependencies and has methods implementing business logic
type App struct {
	Logger  *logrus.Entry
	Storage storage.Storage

	jwtConfig          *jwtConfig
	actuallySendEmails bool
	ses                *ses.SES
	emailConfig        EmailConfig

	clients     []seba.Client
	clientsByID map[string]seba.Client
}

// New creates a new SEBA auth service app instance
func New(cfg Config) (*App, error) {
	appLogger := logger.Create("seba-auth", cfg.LogFormat, cfg.LogLevel)

	jwtConfig, err := createJWTConfig(cfg.JWTPrivateKey, cfg.JWTIssuer)
	if err != nil {
		return nil, err
	}

	if cfg.EmailConfig.AuthnEmailTemplate == nil {
		return nil, errors.New("you must provide an email template")
	}

	for i, cl := range cfg.Clients {
		if cl.GoogleConfig != nil {
			cfg.Clients[i].GoogleConfig.Scopes = []string{"email"}
			cfg.Clients[i].GoogleConfig.Endpoint = google.Endpoint
		}
	}

	app := &App{
		Logger:  appLogger,
		Storage: storage.NewDynamoStorage(cfg.AWSSession, cfg.AWSConfig, cfg.DynamoTableName),

		jwtConfig:          jwtConfig,
		ses:                ses.New(cfg.AWSSession),
		actuallySendEmails: cfg.ActuallySendEmails,
		emailConfig:        cfg.EmailConfig,

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
