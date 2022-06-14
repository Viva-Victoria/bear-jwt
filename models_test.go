package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaims_IsAudience(t *testing.T) {
	claims := Claims{
		Audience: Audience{"office", "api"},
	}

	assert.True(t, claims.IsAudience("office"))
	assert.True(t, claims.IsAudience("api"))
	assert.False(t, claims.IsAudience("admin"))
}
