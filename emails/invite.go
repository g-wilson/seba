package emails

import (
	"bytes"
	"html/template"

	"github.com/aws/aws-sdk-go/service/ses"
)

type inviteTemplateData struct {
	LinkURL string
}

var inviteTemplate = mustCompileinviteTemplate()

func mustCompileinviteTemplate() *template.Template {
	tmpl, err := template.New("invite").Parse(`You have been invite to join an account. Please click here to sign in: {{.LinkURL}}`)
	if err != nil {
		panic(err)
	}

	return tmpl
}

func NewInviteEmail(toAddress, linkURL string) (*ses.SendEmailInput, error) {
	subject := "Create your account"

	var output bytes.Buffer
	err := inviteTemplate.Execute(&output, inviteTemplateData{linkURL})
	if err != nil {
		return nil, err
	}

	outputStr := output.String()

	return &ses.SendEmailInput{
		Destination:      &ses.Destination{ToAddresses: []*string{&toAddress}},
		ReplyToAddresses: []*string{&defaultReplyAddress},
		Source:           &defaultFromAddress,
		Message: &ses.Message{
			Subject: &ses.Content{
				Charset: &charsetUTF8,
				Data:    &subject,
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: &charsetUTF8,
					Data:    &outputStr,
				},
				Text: &ses.Content{
					Charset: &charsetUTF8,
					Data:    &outputStr,
				},
			},
		},
	}, nil
}
