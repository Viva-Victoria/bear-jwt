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

func TestToken_Write(t *testing.T) {
	hs256, err := alg.NewHmacSha(alg.HS256, "secret")
	require.NoError(t, err)

	t.Run("bad algorithm", func(t *testing.T) {
		token := NewToken(NewBasicHeader("NE"), BasicClaims{})
		_, err := token.WriteString()
		require.Error(t, err)
	})

	t.Run("default claims", func(t *testing.T) {
		Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})

		token := NewToken(NewBasicHeader(alg.None), BasicClaims{
			Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
		})

		text, err := token.WriteString()
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJlNjJlN2UxOS05OGY2LTQwZWItOTNlZi04MzNhMzNiNzVhMjIifQ`, strings.TrimSpace(text))
	})

	t.Run("error on sign", func(t *testing.T) {
		Register(alg.None, &errorVerifier{}, &errorVerifier{})
		token := NewToken(NewBasicHeader(alg.None), BasicClaims{
			Id: "e62e7e19-98f6-40eb-93ef-833a33b75a22",
		})

		_, err := token.WriteString()
		require.Error(t, err)
	})

	t.Run("valid hs256", func(t *testing.T) {
		Register(alg.HS256, hs256, hs256)

		token := NewToken(NewBasicHeader(alg.HS256), BasicClaims{
			Id:        "022aee88-4305-497b-8305-404c0c6bac57",
			IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
			ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
		})

		text, err := token.WriteString()
		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0."+
			"iRteOM8kvvHu6ZP3CXRaIg5yHuS8HHQ7Tkq9xNGNcJE", strings.TrimSpace(text))
	})

	t.Run("valid no sign", func(t *testing.T) {
		Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})

		token := NewToken(NewBasicHeader(alg.None), BasicClaims{
			Id:        "022aee88-4305-497b-8305-404c0c6bac57",
			IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
			ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
		})

		buffer, err := token.WriteString()
		require.NoError(t, err)
		assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMCwianRpIjoiMDIyYWVlODgtNDMwNS00OTdiLTgzMDUtNDA0YzBjNmJhYzU3In0`,
			strings.TrimSpace(buffer))
	})

	t.Run("write string", func(t *testing.T) {
		Register(alg.HS256, hs256, hs256)

		token := NewToken(NewBasicHeader(alg.HS256), BasicClaims{
			IssuedAt: NewPosixTime(time.Date(2022, 6, 15, 23, 26, 0, 0, time.UTC)),
		})

		s, err := token.WriteString()
		require.NoError(t, err)
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NTUzMzU1NjB9.01a1NN6zS2AK2Vb18uNGCCGIwwFAAH5tzXh8p5mcPgk", s)

		token.GetHeader().SetAlgorithm(alg.RS256)

		_, err = token.WriteString()
		require.Error(t, err)
	})
}

func TestToken_Validate(t *testing.T) {
	Register(alg.None, &alg.NoneAlgorithm{}, &alg.NoneAlgorithm{})
	token := NewToken(NewBasicHeader(alg.None), BasicClaims{
		ExpiresAt: NewPosixTime(time.Now().Add(-5 * time.Second)),
	})
	assert.Equal(t, StateExpired, token.ValidateNow())

	token = NewToken(NewBasicHeader(alg.None), BasicClaims{
		ExpiresAt: NewPosixTime(time.Now().Add(5 * time.Hour)),
	})
	assert.Equal(t, StateValid, token.ValidateNow())

	token = NewToken(NewBasicHeader(alg.None), BasicClaims{
		ExpiresAt: NewPosixTime(time.Now().Add(5 * time.Hour)),
		IssuedAt:  NewPosixTime(time.Now().Add(5 * time.Hour)),
	})
	assert.Equal(t, StateNotIssued, token.ValidateNow())

	token = NewToken(NewBasicHeader(alg.None), BasicClaims{
		NotBefore: NewPosixTime(time.Now().Add(5 * time.Minute)),
	})
	assert.Equal(t, StateInactive, token.ValidateNow())
	assert.Equal(t, StateValid, token.Validate(time.Now().Add(6*time.Minute)))
}
