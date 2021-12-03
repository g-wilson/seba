package webauthnverificationstart

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	dynamo "github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/webauthn"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/g-wilson/runtime/schema"
)

//go:embed *.json
var fs embed.FS

func Init() (http.Handler, error) {
	log := ctxlog.Create("webauthn-verification-start", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

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
		return nil, err
	}

	f := &Function{
		Storage:  dynamoStorage,
		Clients:  seba.ClientsByID,
		Webauthn: webauthn,
	}

	h, err := http.NewJSONHandler(f.Do, schema.MustLoad(fs, "schema.json"))
	if err != nil {
		return nil, err
	}

	return http.WithMiddleware(
		h,
		http.CreateRequestLogger(log),
		http.JSONErrorHandler,
	), nil
}
