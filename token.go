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

type Token struct {
	header Header
	claims Claims

	signature []byte
}

func NewToken(header Header, claims BasicClaims) *Token {
	return &Token{
		header: header,
		claims: claims,
	}
}

func (t *Token) ReadHeader(h Header) error {
	if err := json.Unmarshal(t.headerBytes, &h); err != nil {
		return err
	}
	t.header = h

	return nil
}

func (t *Token) ReadClaims(c Claims) error {
	if err := json.Unmarshal(t.claimsBytes, &c); err != nil {
		return err
	}
	t.claims = c

	return nil
}

func (t *Token) WriteString() (string, error) {
	buf, err := t.write()
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (t *Token) Validate(moment time.Time) State {
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

func (t *Token) ValidateNow() State {
	return t.Validate(time.Now())
}

func (t *Token) GetHeader() Header {
	return t.header
}

func (t *Token) GetClaims() Claims {
	return t.claims
}

func (t *Token) write() (*bytes.Buffer, error) {
	var (
		headerBytes = t.headerBytes
		claimsBytes = t.claimsBytes
		err         error
	)

	if len(headerBytes) == 0 {
		headerBytes, err = json.Marshal(t.header)
		if err != nil {
			return nil, err
		}
	}

	if len(claimsBytes) == 0 {
		claimsBytes, err = json.Marshal(t.claims)
		if err != nil {
			return nil, err
		}
	}

	headerText := toBase64(headerBytes)
	claimsText := toBase64(claimsBytes)

	algorithm := t.header.GetAlgorithm()
	signer, ok := signers[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm \"%s\"", algorithm)
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
		return nil, err
	}
	if len(signature) > 0 {
		result.Write(_dotBytes)
		result.WriteString(toBase64(signature))
	}

	return result, nil
}
