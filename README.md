# SEBA

> Serverless Email-based Authentication

Add passwordless authentication to your application with a serverless philosophy.

-------

This is primarily an exercise for me to build something real with an entirely serverless philosophy, expand my working knowledge of DynamoDB, and be used as a starter for any side projects.

-------

SEBA is an opinionated service designed specifically for common mobile or JS web applications. It follows similar conventions to oAuth 2, but with some key differences:

#### Authentication, not authorization

oAuth 2 is designed as a protocol for authorization, not authentication. That is, it makes no assumptions about how to verify the user's identity. It specifies how an already-authenticated user may grant permissions so that a (usually 3rd-party) client may access the user's data.

It requires a (usually separate) "Authorization Server", which is a "single-sign-on" style website responsible for authentication and managing the granting of permissions, which is over-the-top and un-necessary if all you want to do is create your own applications.

The goal of SEBA is to provide a simple, sensible way to authenticate a user. It is not concerned with granting scoped permissions to a variet of clients. oAuth 2 is used because of its ubiquity - it is a mature protocol and therefore a solid foundation to implement any token based API security.

#### JSON

oAuth specifies that request bodies must be encoded with `application/x-www-urlencoded`, however I believe it's more common for new projects to use an entirely JSON-based API, so using JSON consistently is easier.

#### Extensions built-in

The PKCE (proof key for code exchange) oAuth extension is used as a fundamental security element to keep the authentication emails safe.

## Architecture

TODO

- API Gateway HTTP API
- OpenID config endpoint
- JWKs endpoint
- Auth endpoint
- Accounts endpoint

## Concepts

#### Access token

- JWTs
- (lack of) Revocation
- Claims

#### Token endpoint

TODO

#### Email tokens

TODO

#### Users and Accounts

TODO

#### Invites

TODO

## Runtime

TODO

## Future development

- Developer configurable email templates
- Developer configurable clients
- Developer configurable callback for obtaining user scopes
- Modular email delivery backends
- Apple ID sign-in as a grant type
- Google sign-in as a grant type

## FAQs

- Why isn't each endpoint a separate Lambda function?

