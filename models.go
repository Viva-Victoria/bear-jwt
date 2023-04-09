package jwt

import (
	"github.com/Viva-Victoria/bear-jwt/alg"
	"strings"
)

type Header interface {
	GetAlgorithm() alg.Algorithm
	SetAlgorithm(a alg.Algorithm)
	GetType() Type
	SetType(t Type)
	GetContentType() string
	GetKeyId() string
}

type BasicHeader struct {
	Algorithm   alg.Algorithm `json:"alg"`
	Type        Type          `json:"typ"`
	ContentType string        `json:"cty,omitempty"`
	KeyId       string        `json:"kid,omitempty"`
}

func NewBasicHeader(alg alg.Algorithm) *BasicHeader {
	return &BasicHeader{
		Algorithm: alg,
		Type:      JsonWebTokenType,
	}
}

func (h *BasicHeader) GetAlgorithm() alg.Algorithm {
	return h.Algorithm
}

func (h *BasicHeader) SetAlgorithm(a alg.Algorithm) {
	h.Algorithm = a
}

func (h *BasicHeader) GetType() Type {
	return h.Type
}

func (h *BasicHeader) SetType(t Type) {
	h.Type = t
}

func (h *BasicHeader) GetContentType() string {
	return h.ContentType
}

func (h *BasicHeader) GetKeyId() string {
	return h.KeyId
}

type Claims interface {
	GetIssuedAt() *PosixTime
	GetExpiresAt() *PosixTime
	GetNotBefore() *PosixTime
}

type BasicClaims struct {
	// IssuedAt contains the time when this token was issued, optional
	IssuedAt *PosixTime `json:"iat,omitempty"`
	// ExpiresAt contains the time after which the token should be rejected, optional
	ExpiresAt *PosixTime `json:"exp,omitempty"`
	// NotBefore contains the time before which token should be rejected, optional
	NotBefore *PosixTime `json:"nbf,omitempty"`
	// Id defines a unique token identifier, usually UUIDv4, required
	Id string `json:"jti,omitempty"`
	// Issuer defines the token issue entity, optional
	Issuer string `json:"iss,omitempty"`
	// Subject contains token issue subject, optional
	Subject string `json:"sub,omitempty"`
	// Audience defines the recipients for which the token is intended, optional
	Audience Audience `json:"aud,omitempty"`
}

func (b BasicClaims) GetIssuedAt() *PosixTime {
	return b.IssuedAt
}

func (b BasicClaims) GetExpiresAt() *PosixTime {
	return b.ExpiresAt
}

func (b BasicClaims) GetNotBefore() *PosixTime {
	return b.NotBefore
}

func (b BasicClaims) IsAudience(s string) bool {
	for _, a := range b.Audience {
		if strings.EqualFold(a, s) {
			return true
		}
	}

	return false
}
