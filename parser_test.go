package jwt

import (
	"testing"

	"github.com/Viva-Victoria/bear-jwt/alg"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nameClaims struct {
	Name string `json:"name"`
}

func TestParser_Parse(t *testing.T) {
	t.Run("normal unsigned", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		token, err := parser.Parse([]byte(`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ`))
		require.NoError(t, err)
		assert.Equal(t, JsonWebTokenType, token.Header.Type)
		assert.Equal(t, alg.None, token.Header.Algorithm)

		claims := nameClaims{}
		require.NoError(t, token.UnmarshalClaims(&claims))
		assert.Equal(t, "John Walker", claims.Name)
	})

	t.Run("bad unsigned", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		_, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		parser := NewParser()
		hs256, err := alg.NewHmacSha(alg.HS256, "not-secret")
		require.NoError(t, err)

		parser.Register(alg.HS256, hs256, hs256)

		_, err = parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		parser := NewParser()
		hs256, err := alg.NewHmacSha(alg.HS256, "secret")
		require.NoError(t, err)

		parser.Register(alg.HS256, hs256, hs256)

		token, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.NoError(t, err)
		assert.Equal(t, JsonWebTokenType, token.Header.Type)
		assert.Equal(t, alg.HS256, token.Header.Algorithm)

		claims := nameClaims{}
		require.NoError(t, token.UnmarshalClaims(&claims))
		assert.Equal(t, "John Walker", claims.Name)
	})
}
