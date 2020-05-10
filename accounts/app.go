package accounts

import (
	"github.com/g-wilson/seba/storage"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/g-wilson/runtime/logger"
	"github.com/sirupsen/logrus"
)

// Config type is used as the argument to the app constructor
type Config struct {
	LogLevel  string
	LogFormat string

	AWSConfig       *aws.Config
	AWSSession      *session.Session
	DynamoTableName string

	ActuallySendEmails bool
	InviteCallbackURL  string
}

// App holds dependencies and has methods implementing business logic
type App struct {
	Logger  *logrus.Entry
	Storage storage.Storage

	actuallySendEmails bool
	inviteCallbackURL  string
	ses                *ses.SES
}

// New creates a new accounts app instance
func New(cfg Config) (*App, error) {
	appLogger := logger.Create("seba-accounts", cfg.LogFormat, cfg.LogLevel)

	app := &App{
		Logger:  appLogger,
		Storage: storage.NewDynamoStorage(cfg.AWSSession, cfg.AWSConfig, cfg.DynamoTableName),

		ses:                ses.New(cfg.AWSSession),
		actuallySendEmails: cfg.ActuallySendEmails,
		inviteCallbackURL:  cfg.InviteCallbackURL,
	}

	return app, nil
}
