package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicClaims_GetId(t *testing.T) {
	var claims BasicClaims
	claims.Id = "random id"

	assert.Equal(t, "random id", claims.GetId())
}

func TestBasicClaims_GetIssuer(t *testing.T) {
	var claims BasicClaims
	claims.Issuer = "auth-service-3.24.56"

	assert.Equal(t, "auth-service-3.24.56", claims.GetIssuer())
}

func TestBasicClaims_GetSubject(t *testing.T) {
	var claims BasicClaims
	claims.Subject = "user#ivanov"

	assert.Equal(t, "user#ivanov", claims.GetSubject())
}

func TestBasicClaims_GetAudience(t *testing.T) {
	testCases := map[string]struct {
		audience Audience
	}{
		"empty": {
			audience: Audience{},
		},
		"nil": {
			audience: nil,
		},
		"fill": {
			audience: Audience{"a", "b"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var claims BasicClaims
			claims.Audience = tc.audience

			assert.Equal(t, tc.audience, claims.GetAudience())
		})
	}
}

func TestBasicClaims_IsAudience(t *testing.T) {
	var claims BasicClaims
	claims.Audience = Audience{"office", "api"}

	assert.True(t, claims.IsAudience("office"))
	assert.True(t, claims.IsAudience("api"))
	assert.False(t, claims.IsAudience("admin"))
}
