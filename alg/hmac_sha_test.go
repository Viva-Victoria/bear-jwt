package alg

import (
	"crypto"
	"encoding/base64"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func toBase64(d []byte) string {
	return base64.RawURLEncoding.EncodeToString(d)
}

func fromBase64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func testHmacSha(a Algorithm, key, payload, signature string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		payloadBytes := []byte(payload)

		hs256, err := NewHmacSha(a, key)
		require.NoError(t, err)

		signatureBytes, err := hs256.Sign(payloadBytes)
		require.NoError(t, err)
		require.Equal(t, signature, toBase64(signatureBytes))

		ok, err := hs256.Verify(payloadBytes, signatureBytes)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestHS(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		hs256, err := NewHmacSha(HS256, "key")
		require.NoError(t, err)

		assert.Equal(t, crypto.SHA256.Size(), hs256.Size())
	})
	t.Run("256", testHmacSha(HS256, "my-secret",
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`,
		`LE-wEGZ8PpTX5RKASzsuKZBm40Wrbj5J3ezy-0FD2fY`))
	t.Run("384", testHmacSha(HS384, "my-secret",
		`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`,
		`CV0AaZkyg82SEdZfeNQHmX-L8SHR9cxz_xz9lidBwrnjTKpB9glEo14WDpCCWNV5`))
	t.Run("512", testHmacSha(HS512, "my-secret",
		`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`,
		`nbvfOhmdw0mJ44iboMfL0ND18n5tKYb2mZdlIFT6fYX8gu0mPm9qPXv2DyTcVcBDp2HC7PRZSfw-eZW6g6JrxQ`))
	t.Run("empty key", func(t *testing.T) {
		_, err := NewHmacSha(HS256, "")
		require.Error(t, err)
	})
	t.Run("incorrect key", func(t *testing.T) {
		primary, err := NewHmacSha(HS256, "primary")
		require.NoError(t, err)

		secondary, err := NewHmacSha(HS256, "secondary")
		require.NoError(t, err)

		payload := []byte("message")
		signature, err := primary.Sign(payload)
		require.NoError(t, err)

		ok, err := secondary.Verify(payload, signature)
		require.NoError(t, err)
		require.False(t, ok)
	})
	t.Run("error digest", func(t *testing.T) {
		hs, err := NewHmacSha(HS256, "test")
		require.NoError(t, err)
		hs.pool = NewHashPool(func() hash.Hash {
			return &errorHash{}
		})

		_, err = hs.Sign([]byte("data"))
		require.Error(t, err)

		_, err = hs.Verify([]byte("data"), []byte("signature"))
		require.Error(t, err)
	})
}

func TestHmacSha_InvalidAlg(t *testing.T) {
	_, err := NewHmacSha(RS256, "test")
	require.Error(t, err)
}
