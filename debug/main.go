package main

import (
	"fmt"
	"html/template"
	"log"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/accounts"
	"github.com/g-wilson/seba/auth"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/devserver"
	"github.com/joho/godotenv"
	"gopkg.in/square/go-jose.v2"
)

var authnTemplateContents = `Sign in by clicking this link: {{.LinkURL}}`
var inviteTemplateContents = `You have been invite to join an account. Please click here to sign in: https://localhost:8080/invite?token={{.InviteToken}}`

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

	authenticator := devserver.NewAuthenticator(keyset, os.Getenv("SEBA_ISSUER"))
	server := devserver.New(listenAddr)

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	authnEmailTemplate, err := template.New("authn").Parse(authnTemplateContents)
	if err != nil {
		panic(fmt.Errorf("error compiling template: %w", err))
	}

	authApp, err := auth.New(auth.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("SEBA_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: false,
		EmailConfig: auth.EmailConfig{
			DefaultFromAddress:  "auth@example.com",
			DefaultReplyAddress: "security@example.com",
			AuthnEmailSubject:   "Sign in link",
			AuthnEmailTemplate:  authnEmailTemplate,
		},

		JWTPrivateKey: os.Getenv("SEBA_PRIVATE_KEY"),
		JWTIssuer:     os.Getenv("SEBA_ISSUER"),

		Clients: []seba.Client{
			seba.Client{
				ID:                      "client_example1",
				EmailAuthenticationURL:  "https://localhost:8080/authenticate",
				EnableInviteConsumption: true,
				DefaultScopes:           []string{"api"},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	inviteEmailTemplate, err := template.New("invite").Parse(inviteTemplateContents)
	if err != nil {
		panic(fmt.Errorf("error compiling template: %w", err))
	}

	accountsApp, err := accounts.New(accounts.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("SEBA_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: false,
		EmailConfig: accounts.EmailConfig{
			DefaultFromAddress:  "auth@example.com",
			DefaultReplyAddress: "security@example.com",
			InviteEmailSubject:  "Join",
			InviteEmailTemplate: inviteEmailTemplate,
		},
	})
	if err != nil {
		panic(err)
	}

	server.AddService("auth", authApp.RPC(), nil)
	server.AddService("accounts", accountsApp.RPC(), authenticator)

	tok, _ := authApp.CreateClientAccessToken("debug", []string{seba.ScopeSebaAdmin})
	server.Log.Infof("client access token: %s", tok)

	server.Listen()
}
