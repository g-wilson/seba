package accounts

import (
	"errors"
	"html/template"

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
	EmailConfig        EmailConfig
}

// EmailConfig type is a group of settings for emails
type EmailConfig struct {
	DefaultReplyAddress string
	DefaultFromAddress  string

	InviteEmailSubject  string
	InviteEmailTemplate *template.Template
}

// App holds dependencies and has methods implementing business logic
type App struct {
	Logger      *logrus.Entry
	Storage     storage.Storage
	emailConfig EmailConfig

	actuallySendEmails bool
	inviteCallbackURL  string
	ses                *ses.SES
}

// New creates a new accounts app instance
func New(cfg Config) (*App, error) {
	appLogger := logger.Create("seba-accounts", cfg.LogFormat, cfg.LogLevel)

	if cfg.EmailConfig.InviteEmailTemplate == nil {
		return nil, errors.New("you must provide an email template")
	}

	app := &App{
		Logger:  appLogger,
		Storage: storage.NewDynamoStorage(cfg.AWSSession, cfg.AWSConfig, cfg.DynamoTableName),

		ses:                ses.New(cfg.AWSSession),
		actuallySendEmails: cfg.ActuallySendEmails,
		emailConfig:        cfg.EmailConfig,
	}

	return app, nil
}
