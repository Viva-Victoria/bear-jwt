package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var (
	pssOptions256 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	pssOptions384 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA384,
	}

	pssOptions512 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	}
)

type RsaSsaPss struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	options    *rsa.PSSOptions
	hash       crypto.Hash
	pool       HashPool
}

func NewRsaSsaPss(a Algorithm, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (RsaSsaPss, error) {
	var hash crypto.Hash
	var options *rsa.PSSOptions

	switch a {
	case PS256:
		hash, options = crypto.SHA256, pssOptions256
	case PS384:
		hash, options = crypto.SHA384, pssOptions384
	case PS512:
		hash, options = crypto.SHA512, pssOptions512
	default:
		return RsaSsaPss{}, fmt.Errorf("algorithm %s is not RSASSA-PSS", a)
	}

	return RsaSsaPss{
		publicKey:  publicKey,
		privateKey: privateKey,
		options:    options,
		hash:       hash,
		pool:       NewHashPool(hash.New),
	}, nil
}

func (r RsaSsaPss) Verify(payload, signature []byte) (bool, error) {
	digest, err := r.pool.Digest(payload)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPSS(r.publicKey, r.hash, digest, signature, r.options)
	if err != nil {
		if err == rsa.ErrVerification {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func (r RsaSsaPss) Size() int {
	return r.privateKey.Size()
}

func (r RsaSsaPss) Sign(payload []byte) ([]byte, error) {
	digest, err := r.pool.Digest(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, r.privateKey, r.hash, digest, r.options)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
