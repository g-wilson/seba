package main

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/storage"
	dynamo "github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/token"
	"github.com/g-wilson/seba/internal/webauthn"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcmethod"
	"github.com/g-wilson/runtime/schema"
)

//go:embed *.json
var fs embed.FS

func main() {
	log := logger.Create("webauthn-registration-complete", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		IDGenerator: storage.GenerateID,
		AWSSession:  awsSession,
		AWSConfig:   awsConfig,
		TableName:   os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	webauthn, err := webauthn.New(webauthn.Params{
		RPDisplayName: os.Getenv("WEBAUTHN_DISPLAY_NAME"),
		RPID:          os.Getenv("AUTH_ISSUER"),
		RPOrigin:      os.Getenv("WEBAUTHN_ORIGIN"),
		Storage:       dynamoStorage,
	})
	if err != nil {
		panic(err)
	}

	creds := &credentials.Credentials{
		Issuer:  os.Getenv("AUTH_ISSUER"),
		Signer:  credentials.MustCreateSigner(os.Getenv("AUTH_PRIVATE_KEY")),
		Storage: dynamoStorage,
		Token:   token.New(),
	}

	handler := &Handler{
		Storage:     dynamoStorage,
		Credentials: creds,
		Clients:     seba.ClientsByID,
		Webauthn:    webauthn,
	}

	rpc := rpcmethod.New(rpcmethod.Params{
		Logger:  log,
		Name:    "complete_webauthn_registration",
		Handler: handler.Do,
		Schema:  schema.MustLoad(fs, "schema.json"),
	})

	lambda.Start(rpc.WrapAPIGatewayHTTP())
}
