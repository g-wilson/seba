package main

import (
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

	authApp, err := auth.New(auth.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("SEBA_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: false,

		JWTPrivateKey: os.Getenv("SEBA_PRIVATE_KEY"),
		JWTIssuer:     os.Getenv("SEBA_ISSUER"),

		Clients: []seba.Client{
			seba.Client{
				ID:                       "client_example1",
				EmailAuthenticationURL:   "https://localhost:8080/authenticate",
				InviteConsumptionEnabled: true,
				DefaultScopes:            []string{"api"},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	accountsApp, err := accounts.New(accounts.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("SEBA_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: false,
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
