package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Viva-Victoria/bear-jwt/alg"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClaims struct {
	Name    string `json:"name,omitempty"`
	Surname string `json:"surname,omitempty"`
	Claims
}

func TestToken_UnmarshalClaims(t *testing.T) {
	token := Token{
		rawClaims: []byte(`{"name": "Kirill", "surname": "Bogatikov"}`),
	}

	claims := testClaims{}
	require.NoError(t, token.UnmarshalClaims(&claims))
	assert.Equal(t, "Kirill", claims.Name)
	assert.Equal(t, "Bogatikov", claims.Surname)
}

func TestToken_Write(t *testing.T) {
	t.Run("default claims", func(t *testing.T) {
		token := Token{
			Header: Header{
				Algorithm: alg.None,
				Type:      JsonWebTokenType,
			},
			Claims: Claims{
				Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
			},
			signer: alg.NoneAlgorithm{},
		}

		buffer, err := token.Write(nil)
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJlNjJlN2UxOS05OGY2LTQwZWItOTNlZi04MzNhMzNiNzVhMjIifQ`,
			strings.TrimSpace(buffer.String()))
	})

	t.Run("error on sign", func(t *testing.T) {
		token := Token{
			Header: Header{
				Algorithm: alg.None,
				Type:      JsonWebTokenType,
			},
			Claims: Claims{
				Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
			},
			signer: errorVerifier{err: errors.New("fail")},
		}

		_, err := token.Write(nil)
		require.Error(t, err)
	})

	t.Run("valid hs256", func(t *testing.T) {
		signer, err := alg.NewHmacSha(alg.HS256, "secret")
		require.NoError(t, err)

		token := Token{
			Header: Header{
				Algorithm: alg.HS256,
				Type:      JsonWebTokenType,
			},
			signer: signer,
		}

		buffer, err := token.Write(testClaims{
			Claims: Claims{
				Id:        "022aee88-4305-497b-8305-404c0c6bac57",
				IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
				ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0.iRteOM8kvvHu6ZP3CXRaIg5yHuS8HHQ7Tkq9xNGNcJE`,
			strings.TrimSpace(buffer.String()))
	})

	t.Run("valid no sign", func(t *testing.T) {
		token := Token{
			Header: Header{
				Algorithm: alg.None,
				Type:      JsonWebTokenType,
			},
			signer: alg.NoneAlgorithm{},
		}

		buffer, err := token.Write(testClaims{
			Claims: Claims{
				Id:        "022aee88-4305-497b-8305-404c0c6bac57",
				IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
				ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0`,
			strings.TrimSpace(buffer.String()))
	})
}

func TestToken_Validate(t *testing.T) {
	token := Token{
		Header: Header{
			Algorithm: alg.None,
			Type:      JsonWebTokenType,
		},
		signer: alg.NoneAlgorithm{},
		Claims: Claims{
			ExpiresAt: NewPosixTime(time.Now().Add(-5 * time.Second)),
		},
	}
	assert.Error(t, token.ValidateNow())

	token.Claims.ExpiresAt = NewPosixTime(time.Now().Add(5 * time.Hour))
	assert.NoError(t, token.ValidateNow())

	token.Claims.IssuedAt = NewPosixTime(time.Now().Add(5 * time.Hour))
	assert.Error(t, token.ValidateNow())
	token.Claims.IssuedAt = nil

	token.Claims.NotBefore = NewPosixTime(time.Now().Add(5 * time.Minute))
	assert.Error(t, token.ValidateNow())
	assert.NoError(t, token.Validate(time.Now().Add(6*time.Minute)))
}
