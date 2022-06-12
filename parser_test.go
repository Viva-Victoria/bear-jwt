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
	parser := NewParser()
	parser.Register(None, alg.None{}, alg.None{})

	t.Run("alg", func(t *testing.T) {
		token, err := parser.Parse([]byte(`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ`))
		require.NoError(t, err)
		assert.Equal(t, JsonWebTokenType, token.Header.Type)
		assert.Equal(t, None, token.Header.Algorithm)

		claims := nameClaims{}
		require.NoError(t, token.UnmarshalClaims(&claims))
		assert.Equal(t, "John Walker", claims.Name)
	})
}
