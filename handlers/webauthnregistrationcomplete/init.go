package webauthnregistrationcomplete

import (
	"context"
	"embed"
	"os"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"
	"github.com/g-wilson/seba/internal/token"
	"github.com/g-wilson/seba/internal/webauthn"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/g-wilson/runtime/schema"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//go:embed *.json
var fs embed.FS

func Init() (http.Handler, error) {
	log := ctxlog.Create("webauthn-registration-complete", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	initCtx, cancelFn := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFn()

	mongoConn, err := mongo.Connect(initCtx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return nil, err
	}

	mongoStorage := mongostorage.New(mongoConn.Database(os.Getenv("MONGODB_DBNAME")))

	webauthn, err := webauthn.New(webauthn.Params{
		RPDisplayName: os.Getenv("WEBAUTHN_DISPLAY_NAME"),
		RPID:          os.Getenv("AUTH_ISSUER"),
		RPOrigin:      os.Getenv("WEBAUTHN_ORIGIN"),
		Storage:       mongoStorage,
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
		mongoStorage.CreateRefreshToken,
	)

	f := &Function{
		Storage:     mongoStorage,
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
