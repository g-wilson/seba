package main

import (
	"context"
	"os"
	"time"

	mongostorage "github.com/g-wilson/seba/internal/storage/mongo"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic("error loading .env file")
	}

	log := ctxlog.Create("mongo_migration", os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	initCtx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFn()

	mongoConn, err := mongo.Connect(initCtx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		log.WithError(err).Fatal("failed")
	}

	err = mongoConn.Ping(initCtx, nil)
	if err != nil {
		log.WithError(err).Fatal("failed")
	}

	mongoStorage := mongostorage.New(mongoConn.Database(os.Getenv("MONGODB_DBNAME")))

	err = mongoStorage.Setup()
	if err != nil {
		log.WithError(err).Fatal("failed")
	}

	log.Info("completed successfully")
}
