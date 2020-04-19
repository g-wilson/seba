package emails

import (
	"bytes"
	"html/template"

	"github.com/aws/aws-sdk-go/service/ses"
)

type accountTemplateData struct {
	LinkURL string
}

var accountTemplate = mustCompileaccountTemplate()

func mustCompileaccountTemplate() *template.Template {
	tmpl, err := template.New("newaccount").Parse(`Please click here to create your account: {{.LinkURL}}`)
	if err != nil {
		panic(err)
	}

	return tmpl
}

func NewAccountEmail(toAddress, linkURL string) (*ses.SendEmailInput, error) {
	subject := "Create your account"

	var output bytes.Buffer
	err := accountTemplate.Execute(&output, accountTemplateData{linkURL})
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
