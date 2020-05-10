package accounts

import (
	"context"

	"github.com/g-wilson/seba/idcontext"

	"github.com/g-wilson/runtime/logger"
	"github.com/g-wilson/runtime/rpcservice"
	"github.com/xeipuuv/gojsonschema"
)

// RPC creates the service responsible for account management methods which require an access token
func (a *App) RPC() *rpcservice.Service {
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
