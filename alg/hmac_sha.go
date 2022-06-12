package alg

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"
)

// HmacSha HMAC SHA256
type HmacSha struct {
	pool HashPool
	hash crypto.Hash
}

func NewHmacSha(a Algorithm, key string) (HmacSha, error) {
	if len(key) == 0 {
		return HmacSha{}, ErrNilKey
	}

	var hashFunc crypto.Hash
	switch a {
	case HS256:
		hashFunc = crypto.SHA256
	case HS384:
		hashFunc = crypto.SHA384
	case HS512:
		hashFunc = crypto.SHA512
	default:
		return HmacSha{}, fmt.Errorf("algorithm %s is not HMAC SHA", a)
	}

	return HmacSha{
		hash: hashFunc,
		pool: NewHashPool(func() hash.Hash {
			return hmac.New(hashFunc.New, []byte(key))
		}),
	}, nil
}

func (h HmacSha) Verify(payload, signature []byte) (bool, error) {
	expected, err := h.Sign(payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected, signature), nil
}

func (h HmacSha) Size() int {
	return h.hash.Size()
}

func (h HmacSha) Sign(payload []byte) ([]byte, error) {
	return h.pool.Digest(payload)
}
