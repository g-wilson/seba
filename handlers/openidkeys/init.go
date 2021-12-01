package openidkeys

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcmethod"
)

//go:embed *.json
var fs embed.FS

const (
	keypath     = "keys.json"
	servicename = "openidkeys"
)

type Response struct {
	Keys []struct {
		Kty string `json:"kty"`
		E   string `json:"e"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
	} `json:"keys"`
}

func Init() *rpcmethod.Method {
	log := logger.Create(servicename, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	file, err := fs.Open(keypath)
	if err != nil {
		panic(fmt.Errorf("cannot open keyfile at %s: %w", keypath, err))
	}

	resBody := Response{}
	fileReader := json.NewDecoder(file)
	err = fileReader.Decode(&resBody)
	if err != nil {
		panic(fmt.Errorf("cannot read keyfile at %s: %w", keypath, err))
	}

	return rpcmethod.New(rpcmethod.Params{
		Logger: log,
		Name:   servicename,
		Handler: func(ctx context.Context) (res *Response, err error) {
			return &resBody, nil
		},
	})
}
