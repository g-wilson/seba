# SEBA

> Serverless Email-based Authentication

A Serverless framework application providing secure passwordless authentication.

SEBA is an opinionated service designed specifically for common mobile or JS web applications. The goal of SEBA is to provide a simple, sensible way to authenticate a user by using an email account as an identity. It is not concerned with granting scoped permissions to a variety of third-party clients.

SEBA issues JWT access tokens for your application. It is specifically designed to be run on AWS Lambda using an HTTP API Gateway for invocation, so that you can take advantage of the provided JWT Authorizer. It also supports hardware second-factor attestation using Webauthn.

Email identity can currently be verified in 2 ways:

- Sending a token in an email to an email address (i.e. "magic link")
- Google sign in authorization code

### oAuth 2.0

SEBA is designed to provide simple authentication - not authorization. oAuth 2 is followed in the API design because of its relative ubiquity in industry. It is a mature protocol and therefore a solid foundation to implement token based security for modern apps. The API follows similar conventions to oAuth 2, but with some key differences:

- No Authorization Server or "single-sign-on" style website responsible for authentication and managing the granting of permissions. SEBA provides identity authentication using email verification. Effectively SEBA provides the Token Endpoint, and delegates the Authorization Server to 3rd parties (email services).

- oAuth specifies that request bodies must be encoded with `application/x-www-urlencoded`, however I believe it's more common for new projects to use an entirely JSON-based API, so using JSON consistently is easier.

- The PKCE (proof key for code exchange) oAuth extension is used as a fundamental security element to make sure the emails are only valid with the correct client session.

- Scope parameter is not used on the token endpoint. This feature is specific to scenarios where the end-user chooses what permissions they want to grant to the clients. Since SEBA is not concerned with authorization at all, it has been left... out of scope.

## Persistence

There is a Storage interface so that multiple storage backends can be developed.

At the moment there is one provider, DynamoDB. It uses a single-table design to minimise provisioning steps, and allow you to use a truly serverless pay-as-you-use pricing model.

## API

### GET /.well-known/openid-configuration

Necessary for use with AWS API Gateway JWT Authorizer, this is a simple endpoint which returns the configuration params necessary for API Gateway to validate the access tokens.

Response:

```
{
	"issuer": "https://identity.example.com",
	"jwks_uri": "https://identity.example.com/.well-known/jwks.json",
	"response_types_supported": [
		"code"
	],
	"subject_types_supported": [
		"public"
	],
	"id_token_signing_alg_values_supported": [
		"RS256"
	],
	"token_endpoint": "https://identity.example.com/2021-09-01/authenticate",
	"response_modes_supported": [
		"query"
	],
	"grant_types_supported": [
		"email_token",
		"refresh_token",
		"google_authz_code"
	],
	"code_challenge_methods_supported": [
		"S256"
	]
}

```

### GET /.well-known/jwks.json

Necessary for use with AWS API Gateway JWT Authorizer, this is a simple endpoint which returns a set of JSON Web Key (JWK) objects against which the JWT access tokens will be validated by API Gateway.

At the time of writing, only RS256 keys are supported by API Gateway JWT Authorizer.

Response:

```
{
	"keys": [
		{
			"kty": "RSA",
			"e": "AQAB",
			"use": "sig",
			"kid": "sig-1630339843",
			"alg": "RS256",
			"n": "43RiU_ORhSnbDiXPjriqU19F0PMm1gHilDmJ4S2XTp572A1Wx1AuoTh0JFmYmwldCYGqJ1Fpa-52Fd_6--9eJ6AiDJyz10TlIooNlXZOAoUvLhrX1UOJ-JZJaXFSrCsDXJC1w1Cyz8snJ1XHrJg8B5qNAHi-T1-ypLZjDwtCTwKvqrID-jB9lUx0Bv_ge2Nom3xvbPy6XvsiF0SJ_RvA9w21KU73NbYkKB3UUwGac0-y6Eq8lTaOKxASEdEqeVSJJswVHzP1y-G1WHmQOCYM9MbCNJrZtQOPvjGTY6Qykg3Q9xJTDqTndCCzUuaSBbHM5Bsukr0yHZ6GuJWgbx3zHw"
		}
	]
}
```

### POST /2021-09-01/send_authentication_email

Sends an email to the provided address with a callback URL to your client. The URL will have query parameters which you can then use on the authentication endpoint.

- The client must generate two secure (high-entropy) strings. One for state (verified by the client) and one for PKCE (verified by the server)

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

- The backend will generate the "magic link" callback URL and send it to the provided email e.g. `https://example.com/signin?code=${CODE}&state=${STATE}`
- The user must follow the URL to your application (e.g. a website or mobile app)
- The client must check that the state parameter of the callback URL matches the persisted one

### POST /2021-09-01/authenticate

This the equivalent oAuth 2 "token endpoint".

#### email_token grant

This grant uses PKCE to bind this request to the same client session as the original send_authentication_email request.

```json
{
	"grant_type": "email_token",
	"code": "{ code param from callback URL }",
	"code_verifier": "{ original PKCE string }",
	"client_id": "your-client-id"
}
```

- The client should provide the original plaintext PKCE string (verifier)
- SEBA will hash the `code_verifier` and check it matches the `code_challenge` from the initial request. This makes sure the email has not been hijacked and it's the same client session as initiated the flow.

#### google grant

The client should authenticate the user with Google and ask for "offline access" in order to obtain a one-time-use token as described in the [Google documentation](https://developers.google.com/identity/sign-in/web/server-side-flow).

```json
{
	"grant_type": "google_authz_code",
	"code": "{ google authz code }",
	"client_id": "your-client-id"
}
```

#### refresh_token grant

You can use the refresh token returned from another grant type to generate new credentials, so that the end-user doesn't have to re-authenticate with their provider.

```json
{
	"grant_type": "refresh_token",
	"code": "{ refresh token }",
	"client_id": "your-client-id"
}
```

#### Response

```json
{
  "access_token": "eyJ...",
  "refresh_token": "0fce8Tl4vkZ8IO5qNhwQwmTbCQMDgnY1",
  "id_token": "eyJ..."
}
```

If you use Go, you can use the included `idcontext` package which provides two utility functions. One takes a `map[string]interface{}` of the JWT claims and will add a SEBA Identity instance to the context, designed to be used in a middleware function of some kind. And the other takes a context and returns the Identity, which you'd use in your application to validate the bearer's identity.

**Access Token claims**

```
{
  "aud": [
    "https://api.example.com"
  ],
  "cid": "some_client_id",
  "exp": 1588957867,
  "iat": 1588954267,
  "iss": "https://identity.example.com",
  "nbf": 1588954267,
  "scope": "api admin",
  "sub": "some_user_id",
  "sfv": false
}
```

The access token provides a user ID as the subject, which you can use in your application.

It is assumed you will use your own separate for storing account data related to your application. SEBA is not designed to provide full-featured user profile or team management system, you can build that on top of the basic authenticated identity flows.

The scope claim can be used for basic permissions checks. At the moment scopes are always determined by the client configuration, they are not part of the oAuth grant. The value is a space-delimited list of strings.

When `sfv` is `true` this means the session can be considered elevated after a hardware-2FA assertion was performed.

**ID Token claims**

```
{
  "aud": [
    "https://api.example.com"
  ],
  "emails": [
    "user@example.com"
  ],
  "exp": 1588957867,
  "iat": 1588954267,
  "iss": "https://identity.example.com",
  "nbf": 1588954267,
  "sub": "some_user_id",
  "sfe": false
}
```

The identity token provides the `user_id` as the subject in the same way as the access token, but it additionally provides the email addresses verified by the user.

`sfe`: "Second Factor Enrolled" is `true` if the user has registered at least one hardware 2FA key credential.

### POST /2021-09-01/start_webauthn_registration

Begins the hardware 2FA registration flow. See [here](https://webauthn.io/) for more info.

Request:

```json
{
	"refresh_token": "aaaxx"
}
```

Response:

```json
{
	"challenge_id": "wanchal_1efxx",
	"attestation_options": {...}
}
```

### POST /2021-09-01/complete_webauthn_registration

Registers a hardware 2FA token against a user using the challenge from `/start_webauthn_registration`.

Request:

```json
{
	"challenge_id": "wanchal_1efxx",
	"attestation_response": {...}
}
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "0fce8Tl4vkZ8IO5qNhwQwmTbCQMDgnY1",
  "id_token": "eyJ..."
}
```

### POST /2021-09-01/start_webauthn_verification

Starts the hardware 2FA verification flow. See [here](https://webauthn.io/) for more info.

Request:

```json
{
	"refresh_token": "aaaxx"
}
```

Response:

```json
{
	"challenge_id": "wanchal_1efxx",
	"assertion_options": {...}
}
```

### POST /2021-09-01/complete_webauthn_verification

Elevates an existing session by asserting the hardware 2FA response using the challenge from `/start_webauthn_verification`.

Request:

```json
{
	"challenge_id": "wanchal_1efxx",
	"assertion_response": {...}
}
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "0fce8Tl4vkZ8IO5qNhwQwmTbCQMDgnY1",
  "id_token": "eyJ..."
}
