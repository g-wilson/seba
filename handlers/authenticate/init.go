package authenticate

import (
	"embed"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	"github.com/g-wilson/seba/internal/storage/dynamo"
	"github.com/g-wilson/seba/internal/token"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/g-wilson/runtime/schema"
)

//go:embed *.json
var fs embed.FS

func Init() (http.Handler, error) {
	log := ctxlog.Create("authenticate", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		AWSSession: awsSession,
		AWSConfig:  awsConfig,
		TableName:  os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	credentialIssuer := credentials.NewIssuer(
		credentials.NewGenerator(
			os.Getenv("AUTH_ISSUER"),
			credentials.MustCreateSigner(os.Getenv("AUTH_PRIVATE_KEY")),
			token.New(),
		),
		dynamoStorage.CreateRefreshToken,
	)

	googleVerifier := google.NewVerifier(google.Config{
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
	})

	f := &Function{
		Token:          token.New(),
		Storage:        dynamoStorage,
		Credentials:    credentialIssuer,
		Clients:        seba.ClientsByID,
		GoogleVerifier: googleVerifier,
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
