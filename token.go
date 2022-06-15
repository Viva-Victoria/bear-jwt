package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Viva-Victoria/bear-jwt/alg"
)

var (
	dotBytes = []byte(".")
)

type Token struct {
	Header    Header
	Claims    Claims
	signature []byte
}

func NewToken(a alg.Algorithm) Token {
	return Token{
		Header: Header{
			Algorithm: a,
			Type:      JsonWebTokenType,
		},
	}
}

func (t Token) Write() (*bytes.Buffer, error) {
	headerJson, err := json.Marshal(t.Header)
	if err != nil {
		return nil, err
	}
	headerText := toBase64(headerJson)

	claimsJson, err := json.Marshal(t.Claims)
	if err != nil {
		return nil, err
	}
	claimsText := toBase64(claimsJson)

	signer, ok := signers[t.Header.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm \"%s\"", t.Header.Algorithm)
	}

	result := new(bytes.Buffer)
	result.Grow(len(headerText) + len(claimsText) + signer.Size() + len(dotBytes)*2)
	result.WriteString(headerText)
	result.Write(dotBytes)
	result.WriteString(claimsText)

	signature, err := signer.Sign(result.Bytes())
	if err != nil {
		return nil, err
	}
	if len(signature) > 0 {
		result.Write(dotBytes)
		result.WriteString(toBase64(signature))
	}

	return result, nil
}

func (t Token) WriteString() (string, error) {
	buf, err := t.Write()
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (t Token) Validate(moment time.Time) State {
	if nbf := t.Claims.NotBefore; nbf != nil && nbf.After(moment) {
		return StateInactive
	}
	if exp := t.Claims.ExpiresAt; exp != nil && exp.Before(moment) {
		return StateExpired
	}
	if iat := t.Claims.IssuedAt; iat != nil && iat.After(moment) {
		return StateNotIssued
	}
	return StateValid
}

func (t Token) ValidateNow() State {
	return t.Validate(time.Now())
}
