package status

import (
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
	"github.com/g-wilson/seba/internal/storage/dynamo"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
)

func Init() (http.Handler, error) {
	log := ctxlog.Create("status", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	dynamoStorage := dynamo.New(dynamo.Params{
		AWSSession: awsSession,
		AWSConfig:  awsConfig,
		TableName:  os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	f := &Function{
		Storage: dynamoStorage,
		Clients: seba.ClientsByID,
	}

	h, err := http.NewJSONHandler(f.Do, nil)
	if err != nil {
		return nil, err
	}

	return http.WithMiddleware(
		h,
		idcontext.Middleware,
		http.CreateRequestLogger(log),
		http.JSONErrorHandler,
	), nil
}
