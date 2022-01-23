package webauthnverificationstart

import (
	"context"
	"embed"
	"os"
	"time"

	"github.com/g-wilson/seba"
	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"
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
	log := ctxlog.Create("webauthn-verification-start", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

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

	f := &Function{
		Storage:  mongoStorage,
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
