# SEBA

> Serverless Email-based Authentication

Add passwordless authentication to your application with a serverless philosophy.

-------

This is primarily an exercise for me to build something real with an entirely serverless philosophy, expand my working knowledge of DynamoDB, and be used as a starter for any side projects.

-------

SEBA is an opinionated service designed specifically for common mobile or JS web applications.

The goal of SEBA is to provide a simple, sensible way to authenticate a user by using an email account as an identity. It is not concerned with granting scoped permissions to a variety of clients.

Email identity can be verified in 3 ways:

- Sending a token in an email to an email address (i.e. "magic link")
- Google sign in authorization code
- Apple ID sign in authorization code (coming soon)

SEBA issues JWT access tokens for your application. It is specifically designed to be run on AWS Lambda using an HTTP API Gateway for invocation, so that you can take advantage of the provided JWT Authorizer.

## Infrastructure setup

```
*-- example.com/.well-known/openid-configuration -------------> [ oauth issuer details ]

*-- example.com/.well-known/jwks.json ------------------------> [ jwt public keys ]

*-- example.com/api -[ HTTP API Gateway ]- /auth/{method+} ---> [ SEBA Lambda ]-[ DynamoDB ]

*-- example.com/api -[ HTTP API Gateway ]- /your-api-here ----> [ JWT Authorizer ] --> [ Your Lambda ]

```

SEBA is hosted as a Lambda function and uses API Gateway's wildcard route matching (`{method+}`) to provide several endpoints with a simple setup.

The `openid-configuration` and `jwks.json` routes can return static files (examples included in this repo) which are necessary for configuring the JWT Authorizer in the HTTP API Gateway. The key file can be used to rotate the key used for access token signing.

There is a second SEBA application which can be hosted as an additional Lambda, which provides some protected endpoints for basic user management. It must be behind a JWT Authorizer in the API Gateway. It is under development so not yet documented.

## Usage in your application

You will need to provision SEBA with your JWT private key, and a list of clients. Clients provide a callback URL which is used to generate the "magic link" SEBA sends to the user's email address. Here you can configure the TTL of access tokens and refresh tokens, and you can set the default `scope` claim.

```go
package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/g-wilson/runtime"
	"github.com/g-wilson/seba/auth"
)

func main() {
	awsConfig := aws.NewConfig().WithRegion(os.Getenv("AWS_REGION"))
	awsSession := session.Must(session.NewSession())

	authnEmailTemplate, err := template.New("authn").Parse(`Sign in by clicking this link: {{.LinkURL}}`)
	if err != nil {
		return nil, fmt.Errorf("error compiling template: %w", err)
	}

	app, err := auth.New(auth.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),

		AWSConfig:       awsConfig,
		AWSSession:      awsSession,
		DynamoTableName: os.Getenv("AUTH_DYNAMO_TABLE_NAME"),

		ActuallySendEmails: (os.Getenv("ACTUALLY_SEND_EMAILS") == "true"),
		EmailConfig: auth.EmailConfig{
			DefaultFromAddress:  "auth@example.com",
			DefaultReplyAddress: "security@example.com",
			AuthnEmailSubject:   "Sign in link",
			AuthnEmailTemplate:  authnEmailTemplate,
		},

		JWTPrivateKey: os.Getenv("AUTH_PRIVATE_KEY"),
		JWTIssuer:     os.Getenv("AUTH_ISSUER"),

		Clients: []seba.Client{
			seba.Client{
				ID:                       "your-client-id",
				EmailAuthenticationURL:   "https://localhost:8080/authenticate",
				InviteConsumptionEnabled: true,
				DefaultScopes:            []string{"api"},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	lambda.Start(runtime.WrapRPCHTTPGateway(app.RPC()))
}
```

### Request flow

Here is the typical API exchange, which should feel familiar if you've used oAuth 2 before:

- Client generates a random string to use as the `state`
- Client generates a random string to use for PKCE
- Both strings are persisted

**/send_authentication_email**

Request:

```json
{
	"email": "user@example.com",
	"state": "{ state string }",
	"code_challenge": "{ sha256 hash of PKCE string }",
	"client_id": "your-client-id"
}
```

Response: 204

- The backend will generate the "magic link" callback URL and send it to the provided email

`https://example.com/signin?code=${CODE}&state=${STATE}`

- The user must follow the URL to your application (e.g. a website or mobile app)
- Client checks that the state parameter of the callback URL matches the persisted one

**/authenticate**

Request:

```json
{
	"grant_type": "email_token",
	"code": "{ code param from callback URL }",
	"code_verifier": "{ original PKCE string }",
	"client_id": "your-client-id"
}
```

- SEBA will hash the `code_verifier` and check it matches the `code_challenge` from the initial request. This makes sure the email has not been hijacked and it's the same client session as initiated the flow.

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "0fce8Tl4vkZ8IO5qNhwQwmTbCQMDgnY1",
  "id_token": "eyJ..."
}
```

If you use Go, you can use the included `idcontext` package which provides two utility functions. One takes a `map[string]interface{}` of the JWT claims and will add a SEBA Identity instance to the context, designed to be used in a middleware function of some kind. And the other takes a context and returns the Identity, which you'd use in your application to validate the bearer's identity.

### Access Token claims

```
{
  "aid": "account_8e488c10-b469-4675-846b-f980e29b951d",
  "aud": [
    "client_awsapigateway"
  ],
  "cid": "client_52842f21-d9fd-4201-b198-c5f0585cb3be",
  "exp": 1588957867,
  "iat": 1588954267,
  "iss": "https://example.com",
  "nbf": 1588954267,
  "scope": "api admin",
  "sub": "user_a71ce329-e1d9-4993-8525-f26bbecc448c"
}
```

The access token provides two identifiers which you can use in your application, a `user_id` and an `account_id`. You should use the `account_id` as a foreign key in your application, not the `user_id`. This will allow you to support transferring accounts, or supporting multiple users per account (teams).

It is assumed you will use your own separate for storing account data related to your application. SEBA is not designed to be extended for a full-featured user profile or team management system.

The scope claim can be used for basic permissions checks. At the moment scopes are always determined by the client configuration, they are not part of the oAuth grant. The value is a space-delimited list of strings.

### ID Token claims

```
{
  "aid": "account_8e488c10-b469-4675-846b-f980e29b951d",
  "aud": [
    "client_awsapigateway"
  ],
  "emails": [
    "user@example.com"
  ],
  "exp": 1588957867,
  "iat": 1588954267,
  "iss": "https://example.com",
  "nbf": 1588954267,
  "sub": "user_a71ce329-e1d9-4993-8525-f26bbecc448c"
}
```

The identity token provides the `user_id` and `account_id` in the same way as the access token, but it additionally provides the email addresses verified by the user.

### Refreshing the session

You can use the refresh token to generate new credentials at any time before the refresh token expires:

**/authenticate**

Request:

```json
{
	"grant_type": "refresh_token",
	"code": "{ refresh token }",
	"client_id": "your-client-id"
}
```

Response: same as the `email_token` grant type.

## Design decisions

oAuth 2 is followed in the API design because of its ubiquity - it is a mature protocol and therefore a solid foundation to implement token based security for modern apps. It follows similar conventions to oAuth 2, but with some key differences:

- No Authorization Server or "single-sign-on" style website responsible for authentication and managing the granting of permissions. SEBA provides identity authentication using email verification. Effectively SEBA provides the Token Endpoint, and delegates the Authorization Server to 3rd parties (email services).

- oAuth specifies that request bodies must be encoded with `application/x-www-urlencoded`, however I believe it's more common for new projects to use an entirely JSON-based API, so using JSON consistently is easier.

- The PKCE (proof key for code exchange) oAuth extension is used as a fundamental security element to make sure the emails are only valid with the correct client session.

- Scope parameter is not used on the token endpoint. This feature is specific to scenarios where the end-user chooses what permissions they want to grant to the clients. Since SEBA is not concerned with authorization at all, it has been left... out of scope.
