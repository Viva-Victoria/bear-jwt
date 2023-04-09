package jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClaims_IsAudience(t *testing.T) {
	var claims BasicClaims
	claims.Audience = Audience{"office", "api"}

	assert.True(t, claims.IsAudience("office"))
	assert.True(t, claims.IsAudience("api"))
	assert.False(t, claims.IsAudience("admin"))
}
