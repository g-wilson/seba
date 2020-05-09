package app

import (
	"context"

	"github.com/g-wilson/seba/idcontext"

	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcservice"
	"github.com/xeipuuv/gojsonschema"
)

// AuthEndpoint creates the RPC service responsible for authenticating users which does not require an access token
func (a *App) AuthEndpoint() *rpcservice.Service {
	return rpcservice.NewService(a.Logger).
		AddMethod("authenticate", a.Authenticate, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "grant_type", "code", "client_id" ],
			"properties": {
				"grant_type": {
					"type": "string",
					"enum": [ "email_token", "invite_token", "refresh_token" ]
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

// AccountsEndpoint creates the RPC service responsible for account management methods which require an access token
func (a *App) AccountsEndpoint() *rpcservice.Service {
	return rpcservice.NewService(a.Logger).
		WithIdentityProvider(idcontext.SetIdentity).
		WithContextProvider(addIdentityLogFields).
		AddMethod("get_user", a.GetUser, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "user_id" ],
			"properties": {
				"user_id": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("get_account", a.GetAccount, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "account_id" ],
			"properties": {
				"account_id": {
					"type": "string",
					"minLength": 1
				}
			}
		}`)).
		AddMethod("create_account", a.CreateAccount, nil).
		AddMethod("send_invite_email", a.SendInviteEmail, gojsonschema.NewStringLoader(`{
			"type": "object",
			"additionalProperties": false,
			"required": [ "email", "account_id" ],
			"properties": {
				"email": {
					"type": "string",
					"format": "email"
				},
				"account_id": {
					"type": "string",
					"minLength": 1
				}
			}
		}`))
}

func addIdentityLogFields(ctx context.Context) context.Context {
	b := idcontext.GetIdentity(ctx)
	reqLogger := logger.FromContext(ctx)

	if reqLogger != nil {
		if b.UserID != "" {
			reqLogger.Update(reqLogger.Entry().WithField("user_id", b.UserID))
		}
		if b.AccountID != "" {
			reqLogger.Update(reqLogger.Entry().WithField("account_id", b.AccountID))
		}
	}

	return ctx
}
