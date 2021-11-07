package main

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	"github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/token"

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
	log := logger.Create("authenticate", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		AWSSession: awsSession,
		AWSConfig:  awsConfig,
		TableName:  os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	credentialIssuer := credentials.NewIssuer(
		dynamoStorage,
		credentials.NewGenerator(
			os.Getenv("AUTH_ISSUER"),
			credentials.MustCreateSigner(os.Getenv("AUTH_PRIVATE_KEY")),
			token.New(),
		),
	)

	googleVerifier := google.NewVerifier(google.Config{
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
	})

	handler := &Handler{
		Token:          token.New(),
		Storage:        dynamoStorage,
		Credentials:    credentialIssuer,
		Clients:        seba.ClientsByID,
		GoogleVerifier: googleVerifier,
	}

	rpc := rpcmethod.New(rpcmethod.Params{
		Logger:  log,
		Name:    "authenticate",
		Handler: handler.Do,
		Schema:  schema.MustLoad(fs, "schema.json"),
	})

	lambda.Start(rpc.WrapAPIGatewayHTTP())
}
