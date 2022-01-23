package sendemail

import (
	"context"
	"embed"
	"fmt"
	html "html/template"
	"os"
	text "text/template"
	"time"

	"github.com/g-wilson/seba"
	emailer "github.com/g-wilson/seba/internal/emailer/ses"
	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"
	"github.com/g-wilson/seba/internal/token"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/g-wilson/runtime/schema"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//go:embed *.json
var fs embed.FS

func Init() (http.Handler, error) {
	log := ctxlog.Create("sendemail", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

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

	initCtx, cancelFn := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFn()

	mongoConn, err := mongo.Connect(initCtx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return nil, err
	}

	mongoStorage := mongostorage.New(mongoConn.Database(os.Getenv("MONGODB_DBNAME")))

	f := &Function{
		Storage: mongoStorage,
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
