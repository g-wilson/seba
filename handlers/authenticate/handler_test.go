package authenticate

import (
	"context"
	"reflect"
	"testing"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/credentials"
	"github.com/g-wilson/seba/internal/google"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"
)

func TestHandler_Do(t *testing.T) {
	type fields struct {
		Token          token.Token
		Storage        storage.Storage
		Credentials    *credentials.Issuer
		Clients        map[string]seba.Client
		GoogleVerifier google.Verifier
	}
	type args struct {
		ctx context.Context
		req *Request
	}

	mockFields := fields{
		Token: &token.Mock{},
		Clients: map[string]seba.Client{
			"client1": {ID: "client1"},
		},
	}

	tests := []struct {
		name        string
		fields      fields
		args        args
		wantRes     *Response
		wantErr     bool
		wantErrCode string
	}{
		{
			name:   "unsupported grant type errors",
			fields: mockFields,
			args: args{
				ctx: context.Background(),
				req: &Request{
					GrantType: "does-not-exist",
					ClientID:  "client1",
				},
			},
			wantRes:     nil,
			wantErr:     true,
			wantErrCode: seba.ErrUnsupportedGrantType.Code,
		},
		{
			name:   "nonexisting client errors",
			fields: mockFields,
			args: args{
				ctx: context.Background(),
				req: &Request{
					GrantType: seba.GrantTypeEmailToken,
					ClientID:  "does-not-exist",
				},
			},
			wantRes:     nil,
			wantErr:     true,
			wantErrCode: seba.ErrClientNotFound.Code,
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
			gotRes, err := h.Do(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Handler.Do() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErrCode != "" {
				if err.Error() != tt.wantErrCode {
					t.Errorf("Handler.Do() error = %v, wantErr %v", err, tt.wantErrCode)
				}
			}
			if gotRes != nil && !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("Handler.Do() = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}

func TestHandler_getOrCreateUserByEmail(t *testing.T) {
	type fields struct {
		Token          token.Token
		Storage        storage.Storage
		Credentials    *credentials.Issuer
		Clients        map[string]seba.Client
		GoogleVerifier google.Verifier
	}
	type args struct {
		ctx   context.Context
		email string
	}

	mockFields := fields{
		Token: &token.Mock{},
		Clients: map[string]seba.Client{
			"client1": {ID: "client1"},
		},
		Storage: &storage.Mock{},
	}

	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantUserID string
	}{
		{
			name:   "existing email",
			fields: mockFields,
			args: args{
				ctx:   context.Background(),
				email: "test@example.com",
			},
			wantErr:    false,
			wantUserID: "user_a",
		},
		{
			name:   "new email",
			fields: mockFields,
			args: args{
				ctx:   context.Background(),
				email: "test-b@example.com",
			},
			wantErr:    false,
			wantUserID: "user_b",
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
			gotUser, err := h.getOrCreateUserByEmail(tt.args.ctx, tt.args.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("Handler.getOrCreateUserByEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUser.ID != tt.wantUserID {
				t.Errorf("Handler.getOrCreateUserByEmail() = %v, want %v", gotUser.ID, tt.wantUserID)
			}
		})
	}
}
