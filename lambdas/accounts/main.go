package main

import (
	seba "github.com/g-wilson/seba/app"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/g-wilson/runtime"
)

func main() {
	app, err := seba.New()
	if err != nil {
		panic(err)
	}

	lambda.Start(runtime.WrapRPCHTTPGateway(app.AccountsEndpoint()))
}
