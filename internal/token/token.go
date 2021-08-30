package token

import (
	"crypto/rand"
	"fmt"
	"io"
)

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Token interface {
	Generate(length int) (string, error)
}

type PRNGTokenGenerator struct{}

func New() *PRNGTokenGenerator {
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Errorf("crypto/rand failed: %w", err))
	}

	return &PRNGTokenGenerator{}
}

func (p *PRNGTokenGenerator) Generate(n int) (string, error) {
	bytes, err := randomBytes(n)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = base62Chars[b%byte(len(base62Chars))]
	}

	return string(bytes), nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
