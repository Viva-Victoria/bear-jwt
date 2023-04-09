package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

var (
	_dotBytes    = []byte(".")
	_buffersPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}
)

type Token[H Header, C Claims] struct {
	header H
	claims C
}

func NewToken[H Header, C Claims](header H, claims C) Token[H, C] {
	return Token[H, C]{
		header: header,
		claims: claims,
	}
}

func (t Token[H, C]) GetHeader() H {
	return t.header
}

func (t Token[H, C]) GetClaims() C {
	return t.claims
}

func (t Token[H, C]) Validate(moment time.Time) State {
	if nbf := t.claims.GetNotBefore(); nbf != nil && nbf.After(moment) {
		return StateInactive
	}
	if exp := t.claims.GetExpiresAt(); exp != nil && exp.Before(moment) {
		return StateExpired
	}
	if iat := t.claims.GetIssuedAt(); iat != nil && iat.After(moment) {
		return StateNotIssued
	}
	return StateValid
}

func (t Token[H, C]) ValidateNow() State {
	return t.Validate(time.Now())
}

func (t Token[H, C]) WriteString() (string, error) {
	headerBytes, err := json.Marshal(t.header)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(t.claims)
	if err != nil {
		return "", err
	}

	headerText := toBase64(headerBytes)
	claimsText := toBase64(claimsBytes)

	algorithm := t.header.GetAlgorithm()
	signer, ok := signers[algorithm]
	if !ok {
		return "", fmt.Errorf("unknown algorithm \"%s\"", algorithm)
	}

	result := _buffersPool.Get().(*bytes.Buffer)
	defer func() {
		result.Reset()
		_buffersPool.Put(result)
	}()

	result.Grow(len(headerText) + len(claimsText) + signer.Size() + len(_dotBytes)*2)
	result.WriteString(headerText)
	result.Write(_dotBytes)
	result.WriteString(claimsText)

	signature, err := signer.Sign(result.Bytes())
	if err != nil {
		return "", err
	}
	if len(signature) > 0 {
		result.Write(_dotBytes)
		result.WriteString(toBase64(signature))
	}

	return result.String(), nil
}
