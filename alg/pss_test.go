package alg

import (
	"crypto"
	"crypto/rsa"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRsaSsaPss(a Algorithm, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, payload []byte) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		rs, err := NewRsaSsaPss(a, privateKey, publicKey)
		require.NoError(t, err)

		signature, err := rs.Sign(payload)
		require.NoError(t, err)

		ok, err := rs.Verify(payload, signature)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestRsaSsaPss(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		rs, err := NewRsaSsaPss(PS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)
		assert.Equal(t, rsa256PrivateKey.Size(), rs.Size())
	})
	t.Run("256", testRsaSsaPss(PS256, rsa256PublicKey, rsa256PrivateKey, []byte("My name Joseph, im a software developer")))
	t.Run("384", testRsaSsaPss(PS384, rsa384PublicKey, rsa384PrivateKey, []byte("BadComedian is not my lover")))
	t.Run("512", testRsaSsaPss(PS512, rsa512PublicKey, rsa512PrivateKey, []byte("No fear, no pain")))
	t.Run("incorrect alg", func(t *testing.T) {
		_, err := NewRsaSsaPss(RS256, rsa256PrivateKeyAlternative, rsa256PublicKey)
		require.Error(t, err)
	})
	t.Run("nil keys", func(t *testing.T) {
		_, err := NewRsaSsaPss(PS256, nil, rsa256PublicKey)
		require.Error(t, err)

		_, err = NewRsaSsaPss(PS256, rsa256PrivateKey, nil)
		require.Error(t, err)
	})
	t.Run("incorrect keys", func(t *testing.T) {
		primary, err := NewRsaSsaPss(PS256, rsa256PrivateKey, rsa256PublicKey)
		require.NoError(t, err)

		secondary, err := NewRsaSsaPss(PS256, rsa256PrivateKeyAlternative, rsa256PublicKeyAlternative)
		require.NoError(t, err)

		payload := []byte("im beach, im a boss")
		signature, err := primary.Sign(payload)
		require.NoError(t, err)

		ok, err := secondary.Verify(payload, signature)
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("error hash", func(t *testing.T) {
		t.Run("bad hash", func(t *testing.T) {
			rs, err := NewRsaSsaPss(PS256, rsa256PrivateKey, rsa256PublicKey)
			require.NoError(t, err)

			rs.hash = crypto.SHA384
			rs.pool = NewHashPool(crypto.SHA384.New)

			_, err = rs.Sign([]byte("message"))
			require.Error(t, err)
		})

		t.Run("error hash", func(t *testing.T) {
			rs, err := NewRsaSsaPss(PS256, rsa256PrivateKey, rsa256PublicKey)
			require.NoError(t, err)

			rs.hash = crypto.SHA256
			rs.pool = NewHashPool(func() hash.Hash {
				return &errorHash{}
			})

			_, err = rs.Verify([]byte("message"), []byte("signature"))
			require.Error(t, err)

			_, err = rs.Sign([]byte("message"))
			require.Error(t, err)
		})
	})
}
