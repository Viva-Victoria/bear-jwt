package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims_IsAudience(t *testing.T) {
	claims := Claims{}
	claims.Audience = Audience{"office", "api"}

	assert.True(t, claims.IsAudience("office"))
	assert.True(t, claims.IsAudience("api"))
	assert.False(t, claims.IsAudience("admin"))
}

func TestClaims_Set(t *testing.T) {
	claims := Claims{}

	err := claims.Set(map[string]string{"key": "value"})
	require.NoError(t, err)

	assert.Equal(t, `{"key":"value"}`, string(claims.raw))
}
