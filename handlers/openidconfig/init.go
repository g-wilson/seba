package openidconfig

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
	configpath  = "config.json"
	servicename = "openidconfig"
)

type Response struct {
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

func Init() *rpcmethod.Method {
	log := logger.Create(servicename, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	file, err := fs.Open(configpath)
	if err != nil {
		panic(fmt.Errorf("cannot open config at %s: %w", configpath, err))
	}

	resBody := Response{}
	fileReader := json.NewDecoder(file)
	err = fileReader.Decode(&resBody)
	if err != nil {
		panic(fmt.Errorf("cannot read config at %s: %w", configpath, err))
	}

	return rpcmethod.New(rpcmethod.Params{
		Logger: log,
		Name:   servicename,
		Handler: func(ctx context.Context) (res *Response, err error) {
			return &resBody, nil
		},
	})
}
