package app

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Hex(inputStr string) string {
	hash := sha256.New()
	hash.Write([]byte(inputStr))
	return hex.EncodeToString(hash.Sum(nil))
}

func ptrStr(str string) *string {
	return &str
}

func ptrBool(b bool) *bool {
	return &b
}
