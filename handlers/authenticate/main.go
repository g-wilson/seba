package main

import (
	"embed"
	"errors"
	"fmt"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/token"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcmethod"
	"github.com/g-wilson/runtime/schema"
	"gopkg.in/square/go-jose.v2"
)

//go:embed *.json
var fs embed.FS

func main() {
	log := logger.Create("authenticate", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		IDGenerator: seba.GenerateID,
		AWSSession:  awsSession,
		AWSConfig:   awsConfig,
		TableName:   os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	googleParams := GoogleOauthConfig{
		ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OAUTH_SECRET"),
	}

	jwtSigner, err := createJWTSigner()
	if err != nil {
		panic(err)
	}

	creds := &credentials.Credentials{
		Issuer:  os.Getenv("AUTH_ISSUER"),
		Signer:  jwtSigner,
		Storage: dynamoStorage,
		Token:   token.New(),
	}

	handler := &Handler{
		Token:        token.New(),
		Storage:      dynamoStorage,
		Credentials:  creds,
		Clients:      seba.ClientsByID,
		GoogleParams: googleParams,
	}

	rpc := rpcmethod.New(rpcmethod.Params{
		Logger:  log,
		Name:    "authenticate",
		Handler: handler.Do,
		Schema:  schema.MustLoad(fs, "schema.json"),
	})

	lambda.Start(rpc.WrapAPIGatewayHTTP())
}

func createJWTSigner() (jose.Signer, error) {
	keyString := os.Getenv("AUTH_PRIVATE_KEY")

	key := jose.JSONWebKey{}
	err := key.UnmarshalJSON([]byte(keyString))
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}
	if !key.Valid() {
		return nil, errors.New("key invalid")
	}

	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
}
