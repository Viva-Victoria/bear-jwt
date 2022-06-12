package jwt

type Header struct {
	Algorithm   Algorithm `json:"alg"`
	Type        Type      `json:"typ"`
	ContentType string    `json:"cty,omitempty"`
	KeyId       string    `json:"kid,omitempty"`
}

type Claims struct {
	// IssuedAt contains the time when this token was issued, optional
	IssuedAt *PosixTime `json:"iat,omitempty"`
	// ExpiresAt contains the time after which the token should be rejected, optional
	ExpiresAt *PosixTime `json:"exp,omitempty"`
	// NotBefore contains the time before which token should be rejected, optional
	NotBefore *PosixTime `json:"nbf,omitempty"`
	// Id defines a unique token identifier, usually UUIDv4, required
	Id string `json:"jti"`
	// Issuer defines the token issue entity, optional
	Issuer string `json:"iss,omitempty"`
	// Subject contains token issue subject, optional
	Subject string `json:"sub,omitempty"`
	// Audience defines the recipients for which the token is intended, optional
	Audience Audience `json:"aud,omitempty"`
}

func (c Claims) IsAudience(audience string) bool {
	for _, aud := range c.Audience {
		if isConstTimeEqualsString(aud, audience) {
			return true
		}
	}

	return false
}
