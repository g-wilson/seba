package webauthnverificationstart

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	dynamo "github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/webauthn"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcmethod"
	"github.com/g-wilson/runtime/schema"
)

//go:embed *.json
var fs embed.FS

func Init() *rpcmethod.Method {
	log := logger.Create("webauthn-verification-start", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		AWSSession: awsSession,
		AWSConfig:  awsConfig,
		TableName:  os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
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

	handler := &Handler{
		Storage:  dynamoStorage,
		Clients:  seba.ClientsByID,
		Webauthn: webauthn,
	}

	return rpcmethod.New(rpcmethod.Params{
		Logger:  log,
		Name:    "webauthn-verification-start",
		Handler: handler.Do,
		Schema:  schema.MustLoad(fs, "schema.json"),
	})
}
