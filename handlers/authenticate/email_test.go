package authenticate

import (
	"context"
	"testing"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"
)

func TestHandler_useEmailToken(t *testing.T) {
	type fields struct {
		Token          token.Token
		Storage        storage.Storage
		Credentials    *credentials.Issuer
		Clients        map[string]seba.Client
		GoogleVerifier google.Verifier
	}
	type args struct {
		ctx      context.Context
		token    string
		client   seba.Client
		verifier *string
	}

	mockFields := fields{
		Token: &token.Mock{},
		Clients: map[string]seba.Client{
			"zero-client":           {ID: "zero-client"},
			"client-supports-email": {ID: "client-supports-email", EnableEmailGrant: true},
		},
		Storage: &storage.Mock{},
	}

	codeVerifier := "a" // "ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=" = base64 encoded string of the sha256 hash

	tests := []struct {
		name        string
		fields      fields
		args        args
		want        string
		want1       string
		wantErr     bool
		wantErrCode string
	}{
		{
			name:   "client email grant not enabled errors",
			fields: mockFields,
			args: args{
				ctx:    context.Background(),
				token:  "code-exists",
				client: seba.Client{ID: "client_a"},
			},
			wantErr:     true,
			wantErrCode: seba.ErrNotSupportedByClient.Code,
		},
		{
			name:   "nil verifier errors",
			fields: mockFields,
			args: args{
				ctx:    context.Background(),
				token:  "code-exists",
				client: seba.Client{ID: "client_a", EnableEmailGrant: true},
			},
			wantErr:     true,
			wantErrCode: seba.ErrPKCEVerifierRequired.Code,
		},
		{
			name:   "code not found errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "a",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrAuthnNotFound.Code,
		},
		{
			name:   "client mismatch errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "client-id-mismatch",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrClientIDMismatch.Code,
		},
		{
			name:   "expired errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "expired",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrAuthnExpired.Code,
		},
		{
			name:   "already verified errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "verified",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrAuthnAlreadyVerified.Code,
		},
		{
			name:   "revoked errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "revoked",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrAuthnRevoked.Code,
		},
		{
			name:   "pkce challenge errors",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "pkce-mismatch",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			wantErr:     true,
			wantErrCode: seba.ErrPKCEChallengeFailed.Code,
		},
		{
			name:   "works with existing user+email",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "code-exists",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			want:  "user_a",
			want1: "a",
		},
		{
			name:   "works with new user+email",
			fields: mockFields,
			args: args{
				ctx:      context.Background(),
				token:    "code-exists-newuser",
				client:   seba.Client{ID: "client_a", EnableEmailGrant: true},
				verifier: &codeVerifier,
			},
			want:  "user_b",
			want1: "b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				Token:          tt.fields.Token,
				Storage:        tt.fields.Storage,
				Credentials:    tt.fields.Credentials,
				Clients:        tt.fields.Clients,
				GoogleVerifier: tt.fields.GoogleVerifier,
			}
			got, got1, err := h.useEmailToken(tt.args.ctx, tt.args.token, tt.args.client, tt.args.verifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("Handler.useEmailToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.wantErrCode != "" {
				if err.Error() != tt.wantErrCode {
					t.Errorf("Handler.useEmailToken() error = %v, wantErr %v", err, tt.wantErrCode)
				}
			}
			if got != tt.want {
				t.Errorf("Handler.useEmailToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Handler.useEmailToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
