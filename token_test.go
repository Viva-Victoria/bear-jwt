package jwt

import (
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
}

func TestToken_UnmarshalClaims(t *testing.T) {
	token := Token{
		Claims: Claims{
			raw: []byte(`{"name": "Kirill", "surname": "Bogatikov"}`),
		},
	}

	claims := testClaims{}
	require.NoError(t, token.Claims.Get(&claims))
	assert.Equal(t, "Kirill", claims.Name)
	assert.Equal(t, "Bogatikov", claims.Surname)
}

func TestToken_Write(t *testing.T) {
	hs256, err := alg.NewHmacSha(alg.HS256, "secret")
	require.NoError(t, err)

	t.Run("bad algorithm", func(t *testing.T) {
		token := NewToken(alg.EdDSA)
		_, err := token.Write()
		require.Error(t, err)
	})

	t.Run("default claims", func(t *testing.T) {
		Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})

		token := NewToken(alg.None)
		token.Claims = Claims{
			BasicClaims: BasicClaims{
				Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
			},
		}

		buffer, err := token.Write()
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJlNjJlN2UxOS05OGY2LTQwZWItOTNlZi04MzNhMzNiNzVhMjIifQ`,
			strings.TrimSpace(buffer.String()))
	})

	t.Run("error on sign", func(t *testing.T) {
		Register(alg.None, &errorVerifier{}, &errorVerifier{})
		token := Token{
			Header: Header{
				Algorithm: alg.None,
				Type:      JsonWebTokenType,
			},
			Claims: Claims{
				BasicClaims: BasicClaims{
					Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
				},
			},
		}

		_, err := token.Write()
		require.Error(t, err)
	})

	t.Run("valid hs256", func(t *testing.T) {
		Register(alg.HS256, hs256, hs256)

		token := Token{
			Header: Header{
				Algorithm: alg.HS256,
				Type:      JsonWebTokenType,
			},
			Claims: Claims{
				BasicClaims: BasicClaims{
					Id:        "022aee88-4305-497b-8305-404c0c6bac57",
					IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
					ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
				},
			},
		}

		buffer, err := token.Write()
		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTc2MDIwMDAsImlhdCI6MTY1NTAxMDAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0."+
			"0_qBmEQ8nUBQ0Ap_AWa4ZhDQ_2QAeGvkE98WCc3UzHs", strings.TrimSpace(buffer.String()))
	})

	t.Run("valid no sign", func(t *testing.T) {
		Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})

		token := Token{
			Header: Header{
				Algorithm: alg.None,
				Type:      JsonWebTokenType,
			},
			Claims: Claims{
				BasicClaims: BasicClaims{
					Id:        "022aee88-4305-497b-8305-404c0c6bac57",
					IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
					ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
				},
			},
		}

		buffer, err := token.Write()
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjE2NTc2MDIwMDAsImlhdCI6MTY1NTAxMDAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0`,
			strings.TrimSpace(buffer.String()))
	})

	t.Run("write string", func(t *testing.T) {
		Register(alg.HS256, hs256, hs256)

		token := NewToken(alg.HS256)
		token.Claims.IssuedAt = NewPosixTime(time.Date(2022, 6, 15, 23, 26, 0, 0, time.UTC))

		s, err := token.WriteString()
		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTUzMzU1NjB9.01a1NN6zS2AK2Vb18uNGCCGIwwFAAH5tzXh8p5mcPgk", s)

		token.Header.Algorithm = alg.RS256
		_, err = token.WriteString()
		require.Error(t, err)
	})
}

func TestToken_Validate(t *testing.T) {
	Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})
	token := Token{
		Header: Header{
			Algorithm: alg.None,
			Type:      JsonWebTokenType,
		},
		Claims: Claims{
			BasicClaims: BasicClaims{
				ExpiresAt: NewPosixTime(time.Now().Add(-5 * time.Second)),
			},
		},
	}
	assert.Equal(t, StateExpired, token.ValidateNow())

	token.Claims.ExpiresAt = NewPosixTime(time.Now().Add(5 * time.Hour))
	assert.Equal(t, StateValid, token.ValidateNow())

	token.Claims.IssuedAt = NewPosixTime(time.Now().Add(5 * time.Hour))
	assert.Equal(t, StateNotIssued, token.ValidateNow())
	token.Claims.IssuedAt = nil

	token.Claims.NotBefore = NewPosixTime(time.Now().Add(5 * time.Minute))
	assert.Equal(t, StateInactive, token.ValidateNow())
	assert.Equal(t, StateValid, token.Validate(time.Now().Add(6*time.Minute)))
}
