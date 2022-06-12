package alg

import (
	"hash"
	"sync"
)

type HashPool struct {
	pool *sync.Pool
}

func NewHashPool(constructor func() hash.Hash) HashPool {
	return HashPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return constructor()
			},
		},
	}
}

func (h HashPool) Digest(data []byte) ([]byte, error) {
	hasher, _ := h.pool.Get().(hash.Hash)
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}
