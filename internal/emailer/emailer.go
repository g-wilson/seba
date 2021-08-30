package emailer

import "context"

type Emailer interface {
	SendAuthenticationEmail(ctx context.Context, emailAddress, linkURL string) error
}
