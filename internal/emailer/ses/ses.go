package ses

import (
	"bytes"
	"context"
	"fmt"
	html "html/template"
	text "text/template"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

type authnEmailTemplateData struct {
	LinkURL string
}

type Params struct {
	SendForReal bool

	DefaultReplyAddress string
	DefaultFromAddress  string

	EmailSubject string

	HTMLEmailTemplate *html.Template
	TextEmailTemplate *text.Template
}

// SESEmailer meets the seba.Emailer interface
type SESEmailer struct {
	ses    *ses.SES
	params Params
}

func New(awsSession *session.Session, cfg Params) *SESEmailer {
	sesClient := ses.New(awsSession)

	return &SESEmailer{
		ses:    sesClient,
		params: cfg,
	}
}

func (e *SESEmailer) SendAuthenticationEmail(ctx context.Context, emailAddress, linkURL string) error {
	var htmlOutput bytes.Buffer
	var textOutput bytes.Buffer

	err := e.params.HTMLEmailTemplate.Execute(&htmlOutput, authnEmailTemplateData{linkURL})
	if err != nil {
		return fmt.Errorf("ses emailer: authn email template failed: %w", err)
	}

	err = e.params.TextEmailTemplate.Execute(&textOutput, authnEmailTemplateData{linkURL})
	if err != nil {
		return fmt.Errorf("ses emailer: authn email template failed: %w", err)
	}

	email := &ses.SendEmailInput{
		Destination:      &ses.Destination{ToAddresses: []*string{&emailAddress}},
		ReplyToAddresses: []*string{&e.params.DefaultReplyAddress},
		Source:           &e.params.DefaultFromAddress,
		Message: &ses.Message{
			Subject: &ses.Content{
				Charset: ptrStr("UTF-8"),
				Data:    &e.params.EmailSubject,
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: ptrStr("UTF-8"),
					Data:    ptrStr(htmlOutput.String()),
				},
				Text: &ses.Content{
					Charset: ptrStr("UTF-8"),
					Data:    ptrStr(textOutput.String()),
				},
			},
		},
	}

	if e.params.SendForReal {
		_, err = e.ses.SendEmailWithContext(ctx, email)
		if err != nil {
			return fmt.Errorf("authn email send failed: %w", err)
		}
	}

	return nil
}

func ptrStr(val string) *string {
	return &val
}
