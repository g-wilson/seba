package openidconfig

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
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

func Init() (http.Handler, error) {
	log := ctxlog.Create(servicename, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	file, err := fs.Open(configpath)
	if err != nil {
		return nil, fmt.Errorf("cannot open config at %s: %w", configpath, err)
	}

	resBody := Response{}
	fileReader := json.NewDecoder(file)
	err = fileReader.Decode(&resBody)
	if err != nil {
		return nil, fmt.Errorf("cannot read config at %s: %w", configpath, err)
	}

	f := func(ctx context.Context) (res *Response, err error) {
		return &resBody, nil
	}

	h, err := http.NewJSONHandler(f, nil)
	if err != nil {
		return nil, err
	}

	return http.WithMiddleware(
		h,
		http.CreateRequestLogger(log),
		http.JSONErrorHandler,
	), nil
}
