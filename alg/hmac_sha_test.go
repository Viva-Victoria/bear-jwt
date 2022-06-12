package alg

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func toBase64(d []byte) string {
	return base64.RawURLEncoding.EncodeToString(d)
}

func TestHS256_Sign(t *testing.T) {
	payload := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`)

	hs256 := NewHS256("my-secret")
	signature, err := hs256.Sign(payload)
	require.NoError(t, err)
	require.Equal(t, `LE-wEGZ8PpTX5RKASzsuKZBm40Wrbj5J3ezy-0FD2fY`, toBase64(signature))

	ok, err := hs256.Verify(payload, signature)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestHS384_Sign(t *testing.T) {
	payload := []byte(`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`)

	hs384 := NewHS384("my-secret")
	signature, err := hs384.Sign(payload)
	require.NoError(t, err)
	require.Equal(t, `CV0AaZkyg82SEdZfeNQHmX-L8SHR9cxz_xz9lidBwrnjTKpB9glEo14WDpCCWNV5`, toBase64(signature))

	ok, err := hs384.Verify(payload, signature)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestHS512_Sign(t *testing.T) {
	payload := []byte(`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMjJhZWU4OC00MzA1LTQ5N2ItODMwNS00MDRjMGM2YmFjNTciLCJpYXQiOjE2NTUwMTAwMDAsImV4cCI6MTY1NzYwMjAwMH0`)

	hs512 := NewHS512("my-secret")
	signature, err := hs512.Sign(payload)
	require.NoError(t, err)
	require.Equal(t, `nbvfOhmdw0mJ44iboMfL0ND18n5tKYb2mZdlIFT6fYX8gu0mPm9qPXv2DyTcVcBDp2HC7PRZSfw-eZW6g6JrxQ`, toBase64(signature))

	ok, err := hs512.Verify(payload, signature)
	require.NoError(t, err)
	assert.True(t, ok)
}
