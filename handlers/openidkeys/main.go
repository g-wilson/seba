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

const keypath = "keys.json"

type Response events.APIGatewayProxyResponse

func main() {
	file, err := fs.Open(keypath)
	if err != nil {
		panic(fmt.Errorf("cannot open keyfile at %s: %w", keypath, err))
	}

	body, err := ioutil.ReadAll(file)
	if err != nil {
		panic(fmt.Errorf("cannot read keyfile at %s: %w", keypath, err))
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
