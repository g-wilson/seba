package sendemail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/internal/emailer"
	"github.com/g-wilson/seba/internal/storage"
	"github.com/g-wilson/seba/internal/token"

	logger "github.com/g-wilson/runtime/ctxlog"
)

type Function struct {
	Storage storage.Storage
	Emailer emailer.Emailer
	Token   token.Token
	Clients map[string]seba.Client
}

type Request struct {
	Email         string `json:"email"`
	State         string `json:"state"`
	ClientID      string `json:"client_id"`
	PKCEChallenge string `json:"pkce_challenge"`
}

func (f *Function) Do(ctx context.Context, req *Request) error {
	log := logger.FromContext(ctx).Entry()

	client, ok := f.Clients[req.ClientID]
	if !ok {
		return seba.ErrClientNotFound
	}

	authzCode, err := f.Token.Generate(32)
	if err != nil {
		return err
	}
	emailFromAddress, err := f.Token.Generate(8)
	if err != nil {
		return err
	}

	fromAddress := fmt.Sprintf("auth_%s@%s", emailFromAddress, f.Emailer.SenderDomain())
	linkURL := fmt.Sprintf("%s?code=%s&state=%s", client.EmailLinkBaseURL, authzCode, url.QueryEscape(req.State))

	log.Debugf("authz_code: %s", authzCode)
	log.Debugf("from_address: %s", fromAddress)
	log.Debugf("link_url: %s", linkURL)

	_, err = f.Storage.CreateAuthentication(ctx, sha256Hex(authzCode), req.Email, req.PKCEChallenge, req.ClientID)
	if err != nil {
		return err
	}

	err = f.Emailer.SendAuthenticationEmail(ctx, req.Email, fromAddress, linkURL)
	if err != nil {
		log.Errorf("authn email sending failed: %v", err)

		return seba.ErrSendingEmail
	}

	return nil
}

func sha256Hex(inputStr string) string {
	digest := sha256.Sum256([]byte(inputStr))
	return hex.EncodeToString(digest[:])
}
