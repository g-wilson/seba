package auth

import (
	"github.com/g-wilson/runtime/rpcservice"
	"github.com/xeipuuv/gojsonschema"
)

// RPC creates the runtime service which can be mounted either in Lambda or in the dev server
func (a *App) RPC() *rpcservice.Service {
	return rpcservice.NewService(a.Logger).
		AddMethod("authenticate", a.Authenticate, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "grant_type", "code", "client_id" ],
			"properties": {
				"grant_type": {
					"type": "string",
					"enum": [ "email_token", "invite_token", "refresh_token", "google" ]
				},
				"code": {
					"type": "string",
					"minLength": 1
				},
				"client_id": {
					"type": "string",
					"minLength": 1
				},
				"pkce_verifier": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("send_authentication_email", a.SendAuthenticationEmail, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "email", "state", "pkce_challenge", "client_id" ],
			"properties": {
				"email": {
					"type": "string",
					"format": "email"
				},
				"state": {
					"type": "string",
					"minLength": 1
				},
				"pkce_challenge": {
					"type": "string",
					"minLength": 1
				},
				"client_id": {
					"type": "string",
					"minLength": 1
				}
			}
		}`))
}
