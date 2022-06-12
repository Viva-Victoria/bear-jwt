package alg

import (
	"crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hash"
	"testing"
)

func testHashPoolDigest(pool HashPool, data, expected string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		digest, err := pool.Digest([]byte(data))
		require.NoError(t, err)
		assert.Equal(t, expected, toBase64(digest))
	}
}

func TestHashPool_Digest(t *testing.T) {
	pool := NewHashPool(func() hash.Hash {
		return crypto.SHA256.New()
	})

	t.Run("simple", testHashPoolDigest(pool, "Hello world!", "wFNeS-K3n_2TKRMFQ2v4iTFOSj-uwF7P_Lt98xrZ5Ro"))
	t.Run("nil", testHashPoolDigest(pool, "", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"))
}
