package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type RsaSsaPkcs1 struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	hash       crypto.Hash
	pool       HashPool
}

func NewRsaSsaPkcs1(a Algorithm, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (RsaSsaPkcs1, error) {
	if publicKey == nil || privateKey == nil {
		return RsaSsaPkcs1{}, ErrNilKey
	}

	var hash crypto.Hash
	switch a {
	case RS256:
		hash = crypto.SHA256
	case RS384:
		hash = crypto.SHA384
	case RS512:
		hash = crypto.SHA512
	default:
		return RsaSsaPkcs1{}, fmt.Errorf("algorithm %s is not RSASSA-PKCS1", a)
	}

	return RsaSsaPkcs1{
		privateKey: privateKey,
		publicKey:  publicKey,
		hash:       hash,
		pool:       NewHashPool(hash.New),
	}, nil
}

func (r RsaSsaPkcs1) Verify(payload, signature []byte) (bool, error) {
	digest, err := r.pool.Digest(payload)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(r.publicKey, r.hash, digest, signature)
	if err != nil {
		if err == rsa.ErrVerification {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func (r RsaSsaPkcs1) Size() int {
	return r.privateKey.Size()
}

func (r RsaSsaPkcs1) Sign(payload []byte) ([]byte, error) {
	digest, err := r.pool.Digest(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, r.hash, digest)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
