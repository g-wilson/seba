package idcontext

import (
	"context"
	"strings"
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

// NewFromClaims attempts to create an Identity from a map of access token claims
func NewFromClaims(claims map[string]interface{}) Identity {
	b := Identity{}

	if sub, ok := claims["sub"].(string); ok {
		b.UserID = sub
	}
	if cid, ok := claims["cid"].(string); ok {
		b.ClientID = cid
	}
	if sc, ok := claims["scope"].(string); ok {
		b.Scopes = strings.Split(sc, " ")
	}

	if sfv, ok := claims["sfv"].(bool); ok {
		b.SecondFactorVerified = sfv
	}

	return b
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

// GetIdentityContext returns an identity from the request context
func GetIdentityContext(ctx context.Context) *Identity {
	val := ctx.Value(ctxkey)

	if claims, ok := val.(*Identity); ok {
		return claims
	}

	return &Identity{}
}

// SetIdentityContext adds an Identity to a Go context, typically the request
func SetIdentityContext(ctx context.Context, b Identity) context.Context {
	ctx = context.WithValue(ctx, ctxkey, b)

	return ctx
}

// IdentityProvider matches the runtime library IdentityProvider type
func IdentityProvider(ctx context.Context, claims map[string]interface{}) context.Context {
	return SetIdentityContext(ctx, NewFromClaims(claims))
}
