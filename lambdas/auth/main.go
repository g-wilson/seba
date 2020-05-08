package main

import (
	seba "github.com/g-wilson/seba/app"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	app, err := seba.New()
	if err != nil {
		panic(err)
	}

	lambda.Start(app.AuthEndpoint().WrapAPIGatewayHTTP())
}
