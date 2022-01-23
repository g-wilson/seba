package status

import (
	"context"
	"os"
	"time"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/idcontext"
	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Init() (http.Handler, error) {
	log := ctxlog.Create("status", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	initCtx, cancelFn := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFn()

	mongoConn, err := mongo.Connect(initCtx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		return nil, err
	}

	mongoStorage := mongostorage.New(mongoConn.Database(os.Getenv("MONGODB_DBNAME")))

	f := &Function{
		Storage: mongoStorage,
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
