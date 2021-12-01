package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/g-wilson/seba/handlers/authenticate"
	"github.com/g-wilson/seba/handlers/openidconfig"
	"github.com/g-wilson/seba/handlers/openidkeys"
	"github.com/g-wilson/seba/handlers/sendemail"
	"github.com/g-wilson/seba/handlers/webauthnregistrationcomplete"
	"github.com/g-wilson/seba/handlers/webauthnregistrationstart"
	"github.com/g-wilson/seba/handlers/webauthnverificationcomplete"
	"github.com/g-wilson/seba/handlers/webauthnverificationstart"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/g-wilson/runtime/rpcmethod"
)

type initFn func() *rpcmethod.Method

var Handlers = map[string]initFn{
	"openidconfig":                 openidconfig.Init,
	"openidkeys":                   openidkeys.Init,
	"authenticate":                 authenticate.Init,
	"sendemail":                    sendemail.Init,
	"webauthnregistrationstart":    webauthnregistrationstart.Init,
	"webauthnregistrationcomplete": webauthnregistrationcomplete.Init,
	"webauthnverificationstart":    webauthnverificationstart.Init,
	"webauthnverificationcomplete": webauthnverificationcomplete.Init,
}

func main() {
	entrypoint := os.Getenv("LAMBDA_GO_ENTRYPOINT")
	if entrypoint == "" {
		panic(fmt.Errorf("no entrypoint defined, LAMBDA_GO_ENTRYPOINT=%s", entrypoint))
	}

	initFn, ok := Handlers[entrypoint]
	if !ok {
		panic(fmt.Errorf("entrypoint %s not found", entrypoint))
	}

	handler := initFn()
	if handler == nil {
		panic(errors.New("entrypoint returned nil handler"))
	}

	lambda.Start(handler.WrapAPIGatewayHTTP())
}
