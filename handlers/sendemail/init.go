package sendemail

import (
	"embed"
	"fmt"
	html "html/template"
	"os"
	text "text/template"

	"github.com/g-wilson/seba"
	emailer "github.com/g-wilson/seba/internal/emailer/ses"
	dynamo "github.com/g-wilson/seba/internal/storage/dynamo"
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
	log := ctxlog.Create("sendemail", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	htmlEmailTemplate, err := html.New("authn").Parse(`<p>Sign in by clicking this link: {{.LinkURL}}</p>`)
	if err != nil {
		return nil, fmt.Errorf("error compiling template: %w", err)
	}

	textEmailTemplate, err := text.New("authn").Parse(`Sign in by clicking this link: {{.LinkURL}}`)
	if err != nil {
		return nil, fmt.Errorf("error compiling template: %w", err)
	}

	sesEmailer := emailer.New(awsSession, emailer.Params{
		SendForReal:         (os.Getenv("ACTUALLY_SEND_EMAILS") == "true"),
		DefaultSenderDomain: os.Getenv("EMAIL_SENDER_DOMAIN"),
		DefaultReplyAddress: os.Getenv("EMAIL_REPLY_ADDRESS"),
		EmailSubject:        "Sign in link",
		HTMLEmailTemplate:   htmlEmailTemplate,
		TextEmailTemplate:   textEmailTemplate,
	})

	dynamoStorage := dynamo.New(dynamo.Params{
		AWSSession: awsSession,
		AWSConfig:  awsConfig,
		TableName:  os.Getenv("AUTH_DYNAMO_TABLE_NAME"),
	})

	f := &Function{
		Storage: dynamoStorage,
		Emailer: sesEmailer,
		Clients: seba.ClientsByID,
		Token:   token.New(),
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
