package jwt

import (
	"github.com/Viva-Victoria/bear-jwt/alg"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicHeader_Compliance(t *testing.T) {
	var basic any = &BasicHeader{}
	_, ok := basic.(Header)
	require.True(t, ok)
}

func TestBasicHeader_GetAlgorithm(t *testing.T) {
	testCases := map[string]struct {
		source   *BasicHeader
		expected alg.Algorithm
	}{
		"NE": {
			source:   NewBasicHeader("NE"),
			expected: "NE",
		},
		"None": {
			source:   NewBasicHeader(alg.None),
			expected: alg.None,
		},
		"HS256": {
			source:   NewBasicHeader(alg.HS256),
			expected: alg.HS256,
		},
		"manual": {
			source: &BasicHeader{
				Algorithm: alg.EdDSA,
			},
			expected: alg.EdDSA,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.source.GetAlgorithm())
		})
	}
}

func TestBasicHeader_SetAlgorithm(t *testing.T) {
	testCases := map[string]struct {
		source *BasicHeader
		alg    alg.Algorithm
	}{
		"NE": {
			source: NewBasicHeader(alg.None),
			alg:    "NE",
		},
		"None": {
			source: NewBasicHeader(alg.None),
			alg:    "NE",
		},
		"HS256": {
			source: NewBasicHeader(alg.HS384),
			alg:    alg.HS256,
		},
		"manual": {
			source: &BasicHeader{
				Algorithm: alg.None,
			},
			alg: alg.EdDSA,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			tc.source.SetAlgorithm(tc.alg)
			assert.Equal(t, tc.alg, tc.source.Algorithm)
		})
	}
}

func TestBasicHeader_GetType(t *testing.T) {
	testCases := map[string]struct {
		typ Type
	}{
		"JWT": {
			typ: JsonWebTokenType,
		},
		"None": {
			typ: "None",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			headers := NewBasicHeader("")
			headers.Type = tc.typ
			assert.Equal(t, tc.typ, headers.GetType())
		})
	}
}

func TestBasicHeader_SetType(t *testing.T) {
	testCases := map[string]struct {
		typ Type
	}{
		"JWT": {
			typ: JsonWebTokenType,
		},
		"None": {
			typ: "None",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			headers := NewBasicHeader("")
			headers.SetType(tc.typ)
			assert.Equal(t, tc.typ, headers.Type)
		})
	}
}

func TestBasicHeader_GetKeyId(t *testing.T) {
	testCases := map[string]struct {
		keyId string
	}{
		"empty": {},
		"random": {
			keyId: "random",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			headers := NewBasicHeader("")
			headers.KeyId = tc.keyId
			assert.Equal(t, tc.keyId, headers.GetKeyId())
		})
	}
}

func TestBasicHeader_SetKeyId(t *testing.T) {
	testCases := map[string]struct {
		keyId string
	}{
		"empty": {},
		"random": {
			keyId: "random",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			headers := NewBasicHeader("")
			headers.SetKeyId(tc.keyId)
			assert.Equal(t, tc.keyId, headers.KeyId)
		})
	}
}
