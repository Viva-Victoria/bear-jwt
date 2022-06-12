package alg

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"sync"
)

// hmacSha private tool for HMAC SHA algorithms
type hmacSha struct {
	pool *sync.Pool
	hash crypto.Hash
}

// newHmacSha creates new hmacSha with specified function pool
func newHmacSha(key string, bit int) hmacSha {
	var hashFunc crypto.Hash
	switch bit {
	case 256:
		hashFunc = crypto.SHA256
	case 384:
		hashFunc = crypto.SHA384
	case 512:
		hashFunc = crypto.SHA512
	}

	return hmacSha{
		hash: hashFunc,
		pool: &sync.Pool{
			New: func() interface{} {
				return hmac.New(hashFunc.New, []byte(key))
			},
		},
	}
}

// sign returns signature for specified payload or error
func (h hmacSha) sign(payload []byte) ([]byte, error) {
	hasher, _ := h.pool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		h.pool.Put(hasher)
	}()

	if _, err := hasher.Write(payload); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

// HS256 HMAC SHA256
type HS256 struct {
	hs hmacSha
}

func NewHS256(key string) HS256 {
	return HS256{
		hs: newHmacSha(key, 256),
	}
}

func (h HS256) Verify(payload, signature []byte) (bool, error) {
	expected, err := h.hs.sign(payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected, signature), nil
}

func (h HS256) Size() int {
	return h.hs.hash.Size()
}

func (h HS256) Sign(payload []byte) ([]byte, error) {
	return h.hs.sign(payload)
}

// HS384 HMAC SHA384
type HS384 struct {
	hs hmacSha
}

func NewHS384(key string) HS384 {
	return HS384{
		hs: newHmacSha(key, 384),
	}
}

func (h HS384) Verify(payload, signature []byte) (bool, error) {
	expected, err := h.hs.sign(payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected, signature), nil
}

func (h HS384) Size() int {
	return h.hs.hash.Size()
}

func (h HS384) Sign(payload []byte) ([]byte, error) {
	return h.hs.sign(payload)
}

// HS512 HMAC SHA512
type HS512 struct {
	hs hmacSha
}

func NewHS512(key string) HS512 {
	return HS512{
		hs: newHmacSha(key, 512),
	}
}

func (h HS512) Verify(payload, signature []byte) (bool, error) {
	expected, err := h.hs.sign(payload)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected, signature), nil
}

func (h HS512) Size() int {
	return h.hs.hash.Size()
}

func (h HS512) Sign(payload []byte) ([]byte, error) {
	return h.hs.sign(payload)
}
