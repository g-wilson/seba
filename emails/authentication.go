package emails

import (
	"bytes"
	"html/template"

	"github.com/aws/aws-sdk-go/service/ses"
)

type authTemplateData struct {
	LinkURL string
}

var authnTemplate = mustCompileAuthnTemplate()

func mustCompileAuthnTemplate() *template.Template {
	tmpl, err := template.New("authn").Parse(`Sign in by clicking this link: {{.LinkURL}}`)
	if err != nil {
		panic(err)
	}

	return tmpl
}

func NewAuthenticationEmail(toAddress, linkURL string) (*ses.SendEmailInput, error) {
	subject := "Sign in"

	var output bytes.Buffer
	err := authnTemplate.Execute(&output, authTemplateData{linkURL})
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
