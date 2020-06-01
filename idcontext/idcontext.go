package idcontext

import (
	"context"
	"strings"
)

type identityContextKey string

var ctxkey = identityContextKey("sebaidentity")

// Identity holds attributes of the bearer who is currently authenticated with an access token
type Identity struct {
	UserID    string
	AccountID string
	ClientID  string
	Scopes    []string
}

// HasScope returns true if the bearer does possess a given scope
func (uc Identity) HasScope(scope string) bool {
	for _, sc := range uc.Scopes {
		if sc == scope {
			return true
		}
	}

	return false
}

// GetIdentity returns the identity of the requester from the request context
func GetIdentity(ctx context.Context) *Identity {
	val := ctx.Value(ctxkey)

	if claims, ok := val.(*Identity); ok {
		return claims
	}

	return &Identity{}
}

// SetIdentity adds the identity of the requester to the request context
func SetIdentity(ctx context.Context, claims map[string]interface{}) context.Context {
	b := &Identity{}

	if sub, ok := claims["sub"].(string); ok {
		b.UserID = sub
	}
	if aid, ok := claims["aid"].(string); ok {
		b.AccountID = aid
	}
	if cid, ok := claims["cid"].(string); ok {
		b.ClientID = cid
	}
	if sc, ok := claims["scope"].(string); ok {
		b.Scopes = strings.Split(sc, " ")
	}

	ctx = context.WithValue(ctx, ctxkey, b)

	return ctx
}
