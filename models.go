package jwt

import (
	"encoding/json"

	"github.com/Viva-Victoria/bear-jwt/alg"
)

type Header struct {
	Algorithm   alg.Algorithm `json:"alg"`
	Type        Type          `json:"typ"`
	ContentType string        `json:"cty,omitempty"`
	KeyId       string        `json:"kid,omitempty"`
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

type Claims struct {
	raw []byte `json:"-"`
	BasicClaims
}

func (c Claims) MarshalJSON() ([]byte, error) {
	temp := make(map[string]interface{})
	if len(c.raw) > 0 {
		err := json.Unmarshal(c.raw, &temp)
		if err != nil {
			return nil, err
		}
	}

	if c.IssuedAt != nil {
		temp["iat"] = c.IssuedAt
	}
	if c.ExpiresAt != nil {
		temp["exp"] = c.ExpiresAt
	}
	if c.NotBefore != nil {
		temp["nbf"] = c.NotBefore
	}

	if len(c.Id) > 0 {
		temp["jti"] = c.Id
	}
	if len(c.Issuer) > 0 {
		temp["iss"] = c.Issuer
	}
	if len(c.Subject) > 0 {
		temp["sub"] = c.Subject
	}
	if len(c.Audience) > 0 {
		temp["aud"] = c.Audience
	}

	return json.Marshal(temp)
}

func (c *Claims) UnmarshalJSON(bytes []byte) error {
	c.raw = bytes

	temp := BasicClaims{}
	err := json.Unmarshal(bytes, &temp)
	if err != nil {
		return err
	}

	c.BasicClaims = temp
	return nil
}

func (c Claims) IsAudience(audience string) bool {
	for _, aud := range c.Audience {
		if isConstTimeEqualsString(aud, audience) {
			return true
		}
	}

	return false
}
func (c Claims) Get(out interface{}) error {
	return json.Unmarshal(c.raw, out)
}

func (c *Claims) Set(in interface{}) (err error) {
	c.raw, err = json.Marshal(in)
	return
}
