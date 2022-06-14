package jwt

import (
	"errors"
	"testing"

	"github.com/Viva-Victoria/bear-jwt/alg"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nameClaims struct {
	Name string `json:"name"`
}

type errorVerifier struct {
	err error
}

func (e errorVerifier) Size() int {
	return 0
}

func (e errorVerifier) Sign(payload []byte) ([]byte, error) {
	return nil, e.err
}

func (e errorVerifier) Verify(payload, signature []byte) (bool, error) {
	return false, e.err
}

func TestParser_Parse(t *testing.T) {
	t.Run("bad header", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		_, err := parser.Parse([]byte(`no-base64.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)

		_, err = parser.Parse([]byte(`ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUIjEKfQ.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)
	})

	t.Run("bad claims", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		_, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.no-base64.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)

		_, err = parser.Parse([]byte(`ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUIjEKfQ.eyJuYW1lIjoiSm9obiBXYWxrZXIifTE.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)
	})

	t.Run("bad signature", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		_, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.no-base64`))
		require.Error(t, err)
	})

	t.Run("bad unsigned", func(t *testing.T) {
		parser := NewParser()
		parser.Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

		_, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

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

	t.Run("invalid signature", func(t *testing.T) {
		parser := NewParser()
		hs256, err := alg.NewHmacSha(alg.HS256, "not-secret")
		require.NoError(t, err)

		parser.Register(alg.HS256, hs256, hs256)

		_, err = parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("error on verify", func(t *testing.T) {
		parser := NewParser()
		errVerifier := &errorVerifier{err: errors.New("fail")}

		parser.Register(alg.HS256, errVerifier, errVerifier)
		_, err := parser.Parse([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
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
