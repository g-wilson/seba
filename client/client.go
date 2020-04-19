package client

import (
	"context"

	"github.com/g-wilson/runtime/rpcclient"
)

type Client struct {
	rpc *rpcclient.RPCClient
}

func NewClient(baseURL, accessToken, clientName string) *Client {
	return &Client{
		rpc: rpcclient.New(baseURL, accessToken, clientName),
	}
}

func (c *Client) ConsumeInvite(ctx context.Context, token string) (res *ConsumeInviteResponse, err error) {
	err = c.rpc.Do(ctx, "consume_invite", &ConsumeInviteRequest{Token: token}, &res)
	return
}

func (c *Client) CreateAccount(ctx context.Context, email string) (res *CreateAccountResponse, err error) {
	err = c.rpc.Do(ctx, "create_account", &CreateAccountRequest{Email: email}, &res)
	return
}

func (c *Client) CreateInvite(ctx context.Context, email, accountID string) (res *CreateInviteResponse, err error) {
	err = c.rpc.Do(ctx, "create_invite", &CreateInviteRequest{Email: email, AccountID: accountID}, &res)
	return
}

func (c *Client) GetAccount(ctx context.Context, accountID string) (res *GetAccountResponse, err error) {
	err = c.rpc.Do(ctx, "get_account", &GetAccountRequest{AccountID: accountID}, &res)
	return
}

func (c *Client) GetUserByEmail(ctx context.Context, email string) (res *GetUserByEmailResponse, err error) {
	err = c.rpc.Do(ctx, "get_user_by_email", &GetUserByEmailRequest{Email: email}, &res)
	return
}

func (c *Client) GetUser(ctx context.Context, userID string) (res *GetUserResponse, err error) {
	err = c.rpc.Do(ctx, "get_user", &GetUserRequest{UserID: userID}, &res)
	return
}
