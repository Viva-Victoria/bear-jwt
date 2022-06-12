package jwt

import (
	"crypto/subtle"
	"encoding/base64"
)

func isConstTimeEqualsString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func toBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func fromBase64(data []byte) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(string(data))
}
