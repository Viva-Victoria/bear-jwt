package jwt

import "strings"

type Claims interface {
	GetIssuedAt() *PosixTime
	GetExpiresAt() *PosixTime
	GetNotBefore() *PosixTime
	GetId() string
	GetIssuer() string
	GetSubject() string
	GetAudience() Audience
	IsAudience(a string) bool
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

func (b BasicClaims) GetId() string {
	return b.Id
}

func (b BasicClaims) GetIssuer() string {
	return b.Issuer
}

func (b BasicClaims) GetSubject() string {
	return b.Subject
}

func (b BasicClaims) GetAudience() Audience {
	return b.Audience
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
