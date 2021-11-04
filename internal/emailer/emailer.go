package emailer

import "context"

type Emailer interface {
	SenderDomain() string
	SendAuthenticationEmail(ctx context.Context, toAddress, fromAddress, linkURL string) error
}
