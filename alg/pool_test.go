package alg

import (
	"crypto"
	"errors"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorHash struct{}

func (e errorHash) Write(p []byte) (n int, err error) {
	return 0, errors.New("fail")
}

func (e errorHash) Sum(b []byte) []byte {
	return nil
}

func (e errorHash) Reset() {}

func (e errorHash) Size() int {
	return 0
}

func (e errorHash) BlockSize() int {
	return 0
}

func testHashPoolDigest(data, expected string) func(t *testing.T) {
	pool := NewHashPool(func() hash.Hash {
		return crypto.SHA256.New()
	})

	return func(t *testing.T) {
		t.Helper()

		digest, err := pool.Digest([]byte(data))
		require.NoError(t, err)
		assert.Equal(t, expected, toBase64(digest))
	}
}

func TestHashPool_Digest(t *testing.T) {

	t.Run("simple", testHashPoolDigest("Hello world!", "wFNeS-K3n_2TKRMFQ2v4iTFOSj-uwF7P_Lt98xrZ5Ro"))
	t.Run("nil", testHashPoolDigest("", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"))
	t.Run("error hash", func(t *testing.T) {
		pool := NewHashPool(func() hash.Hash {
			return &errorHash{}
		})

		_, err := pool.Digest([]byte("message"))
		require.Error(t, err)
	})
}
