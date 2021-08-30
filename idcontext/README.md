The `idcontext` package can be imported in other Go-based serverless applications that use SEBA as an auth server.

The `NewFromClaims` method converts the JWT claims (which would be provided by the API Gateway JWT Authorizer, and in the Lambda event data) into a structured `Identity` type which matches the SEBA conventions.

The `IdentityProvider` method can be used with the [runtime](https://github.com/g-wilson/runtime-helloworld/blob/master/service/main.go#L43) framework which makes running go applications in the Lambda-HTTP environment a piece of cake.
