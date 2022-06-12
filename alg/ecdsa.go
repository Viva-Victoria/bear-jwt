package alg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type ECDSA struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	pool       HashPool
	size       int
}

var (
	ErrNilKey = errors.New("key is nil")
)

func NewECDSA(a Algorithm, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (ECDSA, error) {
	if privateKey == nil || publicKey == nil {
		return ECDSA{}, ErrNilKey
	}

	var hash crypto.Hash
	var keySize int

	switch a {
	case ES256:
		hash, keySize = crypto.SHA256, 64
	case ES384:
		hash, keySize = crypto.SHA384, 96
	case ES512:
		hash, keySize = crypto.SHA512, 132
	default:
		return ECDSA{}, fmt.Errorf("algorithm %s is not ECDSA", a)
	}

	size := roundToBytes(publicKey.Params().BitSize) * 2
	if size != keySize {
		return ECDSA{}, fmt.Errorf("incorrect key size: %d", size)
	}

	return ECDSA{
		privateKey: privateKey,
		publicKey:  publicKey,
		pool:       NewHashPool(hash.New),
		size:       size,
	}, nil
}

func (e ECDSA) Verify(payload, signature []byte) (bool, error) {
	if size := len(signature); size != e.Size() {
		return false, fmt.Errorf("incorrect signature size: %d", size)
	}

	digest, err := e.pool.Digest(payload)
	if err != nil {
		return false, err
	}

	middle := e.Size() / 2
	r := big.NewInt(0).SetBytes(signature[:middle])
	s := big.NewInt(0).SetBytes(signature[middle:])

	return ecdsa.Verify(e.publicKey, digest, r, s), nil
}

func (e ECDSA) Size() int {
	return e.size
}

func (e ECDSA) Sign(payload []byte) ([]byte, error) {
	digest, err := e.pool.Digest(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, digest)
	if err != nil {
		return nil, err
	}

	middle := e.Size() / 2
	signature := make([]byte, e.Size())

	e.copySignaturePart(middle, signature, r.Bytes())
	e.copySignaturePart(e.Size(), signature, s.Bytes())

	return signature, nil
}

func (e ECDSA) copySignaturePart(index int, dst, src []byte) {
	copy(dst[index-len(src):], src)
}

func roundToBytes(bits int) int {
	bytes := bits / 8
	if bits%8 > 0 {
		bytes++
	}

	return bytes
}
