package app

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
					"enum": [ "email_token", "refresh_token", "google_authz_code" ]
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
		}`)).
		AddMethod("start_webauthn_registration", a.StartWebauthnRegistration, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "refresh_token" ],
			"properties": {
				"refresh_token": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("complete_webauthn_registration", a.CompleteWebauthnRegistration, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "refresh_token", "assertion_response" ],
			"properties": {
				"refresh_token": {
					"type": "string",
					"minLength": 1
				},
				"assertion_response": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("start_webauthn_verification", a.StartWebauthnVerification, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "refresh_token" ],
			"properties": {
				"refresh_token": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("complete_webauthn_verification", a.CompleteWebauthnVerification, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "refresh_token", "assertion_response" ],
			"properties": {
				"refresh_token": {
					"type": "string",
					"minLength": 1
				},
				"assertion_response": {
					"type": "string",
					"minLength": 1
				}
			}
		}`))
}
