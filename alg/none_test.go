package alg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNone(t *testing.T) {
	none := NoneAlgorithm{}
	assert.Equal(t, 0, none.Size())

	payload := []byte("i'm a token!")

	sign, err := none.Sign(payload)
	require.NoError(t, err)
	require.Equal(t, 0, len(sign))
	assert.Nil(t, sign)

	ok, err := none.Verify(payload, sign)
	require.NoError(t, err)
	require.True(t, ok)
}
