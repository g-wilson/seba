package webauthnverificationcomplete

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	dynamo "github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/token"
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
	log := ctxlog.Create("webauthn-verification-complete", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

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

	credentialIssuer := credentials.NewIssuer(
		credentials.NewGenerator(
			os.Getenv("AUTH_ISSUER"),
			credentials.MustCreateSigner(os.Getenv("AUTH_PRIVATE_KEY")),
			token.New(),
		),
		dynamoStorage.CreateRefreshToken,
	)

	f := &Function{
		Storage:     dynamoStorage,
		Credentials: credentialIssuer,
		Clients:     seba.ClientsByID,
		Webauthn:    webauthn,
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
