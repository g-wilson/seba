package idcontext

import (
	"context"

	"github.com/g-wilson/runtime/ctxlog"
	"github.com/g-wilson/runtime/http"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-lambda-go/events"
)

type identityContextKey string

var ctxkey = identityContextKey("sebaidentity")

// Identity holds attributes of the bearer of an access token
type Identity struct {
	UserID               string
	ClientID             string
	Scopes               []string
	SecondFactorVerified bool
}

// Exists returns true if an identity is non-zero
func (i Identity) Exists() bool {
	return i.UserID != ""
}

// HasScope returns true if the bearer does possess a given scope
func (i Identity) HasScope(scope string) bool {
	for _, sc := range i.Scopes {
		if sc == scope {
			return true
		}
	}

	return false
}

// GetIdentityContext returns an identity from the request context
func GetIdentityContext(ctx context.Context) Identity {
	val := ctx.Value(ctxkey)

	if id, ok := val.(Identity); ok {
		return id
	}

	return Identity{}
}

// SetIdentityContext adds an Identity to a Go context, typically the request
func SetIdentityContext(ctx context.Context, i Identity) context.Context {
	ctx = context.WithValue(ctx, ctxkey, i)

	return ctx
}

// Middleware is a runtime (the library) compatible middlewhere which will convert
// the JWT Authorizer claims in a HTTP API Gateway Lambda event into an Identity struct
func Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayProxyResponse, error) {
		authdata := event.RequestContext.Authorizer.JWT

		i := Identity{
			Scopes: authdata.Scopes,
		}

		if sub, ok := authdata.Claims["sub"]; ok {
			i.UserID = sub
		}
		if cid, ok := authdata.Claims["cid"]; ok {
			i.ClientID = cid
		}
		if sfv, ok := authdata.Claims["sfv"]; ok {
			i.SecondFactorVerified = sfv == "true"
		}

		ctx = SetIdentityContext(ctx, i)

		if reqLog := ctxlog.FromContext(ctx); reqLog != nil {
			reqLog.Update(
				reqLog.Entry().WithFields(logrus.Fields{
					"auth_user_id":       i.UserID,
					"auth_client_id":     i.ClientID,
					"auth_second_factor": i.SecondFactorVerified,
					"auth_scopes":        i.Scopes,
				}),
			)
		}

		return h.Handle(ctx, event)
	})
}
