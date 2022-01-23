package authenticate

import (
	"context"
	"embed"
	"os"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"
	"github.com/g-wilson/seba/internal/token"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/g-wilson/runtime/schema"
)

//go:embed *.json
var fs embed.FS

func Init() (http.Handler, error) {
	log := ctxlog.Create("authenticate", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	initCtx, cancelFn := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFn()

	mongoConn, err := mongo.Connect(initCtx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return nil, err
	}

	mongoStorage := mongostorage.New(mongoConn.Database(os.Getenv("MONGODB_DBNAME")))

	credentialIssuer := credentials.NewIssuer(
		credentials.NewGenerator(
			os.Getenv("AUTH_ISSUER"),
			credentials.MustCreateSigner(os.Getenv("AUTH_PRIVATE_KEY")),
			token.New(),
		),
		mongoStorage.CreateRefreshToken,
	)

	googleVerifier := google.NewVerifier(google.Config{
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
	})

	f := &Function{
		Token:          token.New(),
		Storage:        mongoStorage,
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
