package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_isConstTimeEqualsString(t *testing.T) {
	assert.True(t, isConstTimeEqualsString("test", "test"))
	assert.False(t, isConstTimeEqualsString("True", "true"))
	assert.False(t, isConstTimeEqualsString("True", "False"))
}

func Test_toBase64(t *testing.T) {
	assert.Equal(t, "UGVuemEgY2l0eQ", toBase64([]byte("Penza city")))
	assert.Equal(t, "U3RyaXZlIG5vdCBmb3Igc3VjY2VzcywgYnV0IGZvciB0aGUgdmFsdWVzIHRoYXQgaXQgZ2l2ZXM", toBase64([]byte("Strive not for success, but for the values that it gives")))
	assert.NotEqual(t, "U3RyaXZlIG5vdCBmb3Igc3VjY2VzcywgYnV0IGZvciB0aGUgdmFsdWVzIHRoYXQgaXQgZ2l2ZXM", toBase64([]byte("Penza city")))
}

func testFromBase64(t *testing.T, expected, base64 string) {
	data, err := fromBase64([]byte(base64))
	require.NoError(t, err)
	assert.Equal(t, expected, string(data))
}

func Test_fromBase64(t *testing.T) {
	testFromBase64(t, "Penza city", "UGVuemEgY2l0eQ")
	testFromBase64(t, "Strive not for success, but for the values that it gives", "U3RyaXZlIG5vdCBmb3Igc3VjY2VzcywgYnV0IGZvciB0aGUgdmFsdWVzIHRoYXQgaXQgZ2l2ZXM")
}
