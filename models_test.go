package jwt

import (
	"encoding/json"
	"fmt"
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

func TestClaims_JSON(t *testing.T) {
	t.Run("valid raw claims", func(t *testing.T) {
		claims := Claims{
			raw: []byte(`{"key":"value"}`),
		}

		b, err := json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, `{"key":"value"}`, string(b))
	})
	t.Run("invalid raw claims", func(t *testing.T) {
		claims := Claims{
			raw: []byte(`{"key":123"value"}`),
		}

		_, err := json.Marshal(claims)
		require.Error(t, err)

		claims = Claims{}
		err = json.Unmarshal([]byte(`{"key": 12`), &claims)
		require.Error(t, err)
	})
	t.Run("mapping", func(t *testing.T) {
		claims := Claims{}
		claims.IssuedAt = NewPosixTime(time12062022)
		b, err := json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf(`{"iat":%d}`, time12062022.Unix()), string(b))

		claims = Claims{}
		claims.ExpiresAt = NewPosixTime(time12062022)
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf(`{"exp":%d}`, time12062022.Unix()), string(b))

		claims = Claims{}
		claims.NotBefore = NewPosixTime(time12062022)
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf(`{"nbf":%d}`, time12062022.Unix()), string(b))

		claims = Claims{}
		claims.Id = "uuid"
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, `{"jti":"uuid"}`, string(b))

		claims = Claims{}
		claims.Issuer = "admin"
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, `{"iss":"admin"}`, string(b))

		claims = Claims{}
		claims.Subject = "test"
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, `{"sub":"test"}`, string(b))

		claims = Claims{}
		claims.Audience = Audience{"office", "home"}
		b, err = json.Marshal(claims)
		require.NoError(t, err)
		assert.Equal(t, `{"aud":["office","home"]}`, string(b))
	})
}

func TestClaims_Set(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		claims := Claims{}

		err := claims.Set(map[string]string{"key": "value"})
		require.NoError(t, err)

		assert.Equal(t, `{"key":"value"}`, string(claims.raw))
	})
}
