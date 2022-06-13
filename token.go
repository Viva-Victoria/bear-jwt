package jwt

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/Viva-Victoria/bear-jwt/alg"
)

var (
	dotBytes = []byte(".")
)

type Token struct {
	Header    Header
	Claims    Claims
	signer    alg.Signer
	signature []byte
	rawClaims []byte
}

func (t Token) UnmarshalClaims(out interface{}) error {
	return json.Unmarshal(t.rawClaims, out)
}

func (t Token) Write(claims interface{}) (*bytes.Buffer, error) {
	headerJson, err := json.Marshal(t.Header)
	if err != nil {
		return nil, err
	}
	headerText := toBase64(headerJson)

	if claims == nil {
		claims = t.Claims
	}

	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	claimsText := toBase64(claimsJson)

	result := new(bytes.Buffer)
	result.Grow(len(headerText) + len(claimsText) + t.signer.Size() + len(dotBytes)*2)
	result.WriteString(headerText)
	result.Write(dotBytes)
	result.WriteString(claimsText)

	signature, err := t.signer.Sign(result.Bytes())
	if err != nil {
		return nil, err
	}
	if len(signature) > 0 {
		result.Write(dotBytes)
		result.WriteString(toBase64(signature))
	}

	return result, nil
}

func (t Token) Validate(moment time.Time) error {
	if nbf := t.Claims.NotBefore; nbf != nil && nbf.After(moment) {
		return ErrInactive
	}
	if exp := t.Claims.ExpiresAt; exp != nil && exp.Before(moment) {
		return ErrExpired
	}
	if iat := t.Claims.IssuedAt; iat != nil && iat.After(moment) {
		return ErrNotIssued
	}
	return nil
}

func (t Token) ValidateNow() error {
	return t.Validate(time.Now())
}
