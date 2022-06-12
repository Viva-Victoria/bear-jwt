package jwt

import (
	"bear-jwt/alg"
	"strings"
	"testing"
	"time"

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
	token := Token{
		Header: Header{
			Algorithm: None,
			Type:      JsonWebTokenType,
		},
		signer: alg.None{},
	}

	buffer, err := token.Write(testClaims{
		Claims: Claims{
			Id:        "022aee88-4305-497b-8305-404c0c6bac57",
			IssuedAt:  NewPosixTime(time.Date(2022, 06, 12, 5, 0, 0, 0, time.UTC)),
			ExpiresAt: NewPosixTime(time.Date(2022, 07, 12, 5, 0, 0, 0, time.UTC)),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`,
		strings.TrimSpace(buffer.String()))
}

func TestToken_Validate(t *testing.T) {
	token := Token{
		Header: Header{
			Algorithm: None,
			Type:      JsonWebTokenType,
		},
		signer: alg.None{},
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
