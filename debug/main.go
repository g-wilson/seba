package main

import (
	"fmt"
	"log"
	"os"
	"text/template"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/app"
	"golang.org/x/oauth2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/devserver"
	"github.com/joho/godotenv"
	"gopkg.in/square/go-jose.v2"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func main() {
	listenAddr := "127.0.0.1:" + os.Getenv("HTTP_PORT")

	keyset := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}

	privKey := jose.JSONWebKey{}
	err := privKey.UnmarshalJSON([]byte(os.Getenv("SEBA_PRIVATE_KEY")))
	if err != nil || !privKey.Valid() {
		panic("error parsing key")
	}

	keyset.Keys = append(keyset.Keys, privKey.Public())

	// authenticator := devserver.NewAuthenticator(keyset, os.Getenv("SEBA_ISSUER"))
	server := devserver.New(listenAddr)

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	authnEmailTemplate, err := template.New("authn").Parse(`Sign in by clicking this link: {{.LinkURL}}`)
	if err != nil {
		panic(fmt.Errorf("error compiling template: %w", err))
	}

	sebaInstance, err := app.New(seba.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("SEBA_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: false,
		EmailConfig: seba.EmailConfig{
			DefaultFromAddress:  "auth@example.com",
			DefaultReplyAddress: "security@example.com",
			AuthnEmailSubject:   "Sign in link",
			AuthnEmailTemplate:  authnEmailTemplate,
		},

		JWTPrivateKey: os.Getenv("SEBA_PRIVATE_KEY"),
		JWTIssuer:     os.Getenv("SEBA_ISSUER"),

		WebauthnDisplayName: "Example",
		WebauthnID:          "example.com",

		Clients: []seba.Client{
			seba.Client{
				ID:                     "example_client1",
				EmailAuthenticationURL: "https://localhost:8080/authenticate",
				DefaultScopes:          []string{"api"},
				RefreshTokenTTL:        90 * 24 * time.Hour,
				GoogleConfig: &oauth2.Config{
					ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
					ClientSecret: os.Getenv("GOOGLE_OAUTH_SECRET"),
					RedirectURL:  "https://localhost:8080",
				},
				WebauthnOrigin: "https://localhost:8080",
			},
		},
	})
	if err != nil {
		panic(err)
	}

	server.AddService("auth", sebaInstance.RPC(), nil)

	tok, _ := sebaInstance.CreateBasicCredentials("debug", []string{seba.ScopeSebaAdmin})
	server.Log.Infof("client access token: %s", tok)

	server.Listen()
}
