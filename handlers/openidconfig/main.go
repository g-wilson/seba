package main

import (
	"context"
	"embed"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

//go:embed *.json
var fs embed.FS

const configpath = "config.json"

type Response events.APIGatewayProxyResponse

func main() {
	file, err := fs.Open(configpath)
	if err != nil {
		panic(fmt.Errorf("cannot open config at %s: %w", configpath, err))
	}

	body, err := ioutil.ReadAll(file)
	if err != nil {
		panic(fmt.Errorf("cannot read config at %s: %w", configpath, err))
	}

	lambda.Start(func(ctx context.Context) (Response, error) {
		resp := Response{
			StatusCode:      200,
			IsBase64Encoded: false,
			Body:            string(body),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}

		return resp, nil
	})
}
