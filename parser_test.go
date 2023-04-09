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
	BasicClaims
}

type errorVerifier struct {
}

func (e errorVerifier) Size() int {
	return 0
}

func (e errorVerifier) Sign(_ []byte) ([]byte, error) {
	return nil, errors.New("fail")
}

func (e errorVerifier) Verify(_, _ []byte) (bool, error) {
	return false, errors.New("fail")
}

func TestParser_Parse(t *testing.T) {
	Register(alg.None, alg.NoneAlgorithm{}, alg.NoneAlgorithm{})

	t.Run("bad header", func(t *testing.T) {
		_, err := ParseDefault([]byte(`no-base64.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)

		_, err = ParseDefault([]byte(`ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUIjEKfQ.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)
	})

	t.Run("bad claims", func(t *testing.T) {
		_, err := ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.no-base64.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)

		_, err = ParseDefault([]byte(`ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUIjEKfQ.eyJuYW1lIjoiSm9obiBXYWxrZXIifTE.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		assert.Error(t, err)
	})

	t.Run("bad signature", func(t *testing.T) {
		_, err := ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.no-base64`))
		require.Error(t, err)
	})

	t.Run("bad unsigned", func(t *testing.T) {
		_, err := ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("normal unsigned", func(t *testing.T) {
		token, err := Parse[*BasicHeader, nameClaims]([]byte(`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ`))
		require.NoError(t, err)
		assert.Equal(t, JsonWebTokenType, token.GetHeader().GetType())
		assert.Equal(t, alg.None, token.GetHeader().GetAlgorithm())

		assert.Equal(t, "John Walker", token.GetClaims().Name)
	})

	t.Run("invalid signature", func(t *testing.T) {
		hs256, err := alg.NewHmacSha(alg.HS256, "not-secret")
		require.NoError(t, err)
		Register(alg.HS256, hs256, hs256)

		_, err = ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("error on verify", func(t *testing.T) {
		errVerifier := &errorVerifier{}
		Register(alg.HS256, errVerifier, errVerifier)

		_, err := ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		hs256, err := alg.NewHmacSha(alg.HS256, "secret")
		require.NoError(t, err)

		Register(alg.HS256, hs256, hs256)

		token, err := Parse[*BasicHeader, nameClaims]([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBXYWxrZXIifQ.7UmH--UfHa2MPdiP9tX--FK_1tgojlAZSu2R7RyeEaY`))
		require.NoError(t, err)
		assert.Equal(t, JsonWebTokenType, token.GetHeader().Type)
		assert.Equal(t, alg.HS256, token.GetHeader().Algorithm)

		assert.Equal(t, "John Walker", token.GetClaims().Name)
	})

	t.Run("bad data", func(t *testing.T) {
		_, err := ParseDefault(nil)
		require.EqualError(t, ErrNoData, err.Error())

		_, err = ParseDefault([]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`))
		require.EqualError(t, ErrIncorrectFormat, err.Error())

		_, err = ParseDefault([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXQSJ9." +
			"eyJleHAiOjE2NTc2MDIwMDAsImlhdCI6MTY1NTAxMDAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0." +
			"ob-oT_SxYuync2i501PkErDHDyB3JmhI1lDd-IuLc3U"))
		require.Error(t, err)

		_, err = ParseDefault([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXQSJ9." +
			"eyJleHAiOjE2NTc2MDIwMDAsMSJpYXQiOjE2NTUwMTAwMDAsImp0aSI6IjAyMmFlZTg4LTQzMDUtNDk3Yi04MzA1LTQwNGMwYzZiYWM1NyJ9." +
			"ob-oT_SxYuync2i501PkErDHDyB3JmhI1lDd-IuLc3U"))
		require.Error(t, err)
	})
}
