# Well Known directory

This is provided as an example. In order to use SEBA with your HTTP API Gateway JWT Authorizer you'll have to host these two files somewhere.

### openid-configuration

This file may be used by oAuth clients for a dynamic configuration. And it's required by API Gateway so it knows what your JWT issuer is, and where it can find the list of valid public keys.

### jwks.json

This file publishes your public keys on which the JWT Authorizer will verify the token.

At the time of writing, AWS only supports RSA keys.

SEBA uses one provided private key for signatures, but you can add multiple keys here to facilitate key rotation.
