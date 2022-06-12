package alg

import (
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func testRsaSsaPss(a Algorithm, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, payload []byte) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		rs, err := NewRsaSsaPss(a, publicKey, privateKey)
		require.NoError(t, err)

		signature, err := rs.Sign(payload)
		require.NoError(t, err)

		ok, err := rs.Verify(payload, signature)
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestRsaSsaPss(t *testing.T) {
	t.Run("256", testRsaSsaPss(PS256, rsa256PublicKey, rsa256PrivateKey, []byte("My name Joseph, im a software developer")))
	t.Run("384", testRsaSsaPss(PS384, rsa384PublicKey, rsa384PrivateKey, []byte("BadComedian is not my lover")))
	t.Run("512", testRsaSsaPss(PS512, rsa512PublicKey, rsa512PrivateKey, []byte("No fear, no pain")))
}
