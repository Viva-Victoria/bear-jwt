package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/Viva-Victoria/bear-jwt/alg"
)

var (
	verifiers = make(map[alg.Algorithm]alg.Verifier)
	signers   = make(map[alg.Algorithm]alg.Signer)
)

// Register registers new verifier and signer for specified algorithm.
// If another implementation of the algorithm was registered earlier, it will be overwritten
func Register(algorithm alg.Algorithm, verifier alg.Verifier, signer alg.Signer) {
	verifiers[algorithm] = verifier
	signers[algorithm] = signer
}

// Parse returns Token parsed from byte array data or error if some troubles occurred
func Parse(data []byte) (*Token, error) {
	if len(data) == 0 {
		return nil, ErrNoData
	}

	firstDot := bytes.Index(data, _dotBytes)
	if firstDot == -1 {
		return nil, ErrIncorrectFormat
	}

	secondDot := bytes.Index(data[firstDot+1:], _dotBytes)
	if secondDot == -1 {
		secondDot = len(data)
	} else {
		secondDot += firstDot + 1
	}

	payloadBytes := data[:secondDot]
	headerBytes, err := fromBase64(payloadBytes[:firstDot])
	if err != nil {
		return nil, fmt.Errorf("bad header: %v", err)
	}

	claimsBytes, err := fromBase64(payloadBytes[firstDot+1:])
	if err != nil {
		return nil, fmt.Errorf("bad claims: %v", err)
	}

	var signatureBytes []byte
	if len(payloadBytes) < len(data) {
		d := data[secondDot+1:]
		signatureBytes, err = fromBase64(d)
		if err != nil {
			return nil, fmt.Errorf("bad signature: %v", err)
		}
	}

	header := NewBasicHeader(alg.None)
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if header.Type != JsonWebTokenType {
		return nil, fmt.Errorf("token type \"%s\" not supported", header.Type)
	}

	verifier, ok := verifiers[header.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm \"%s\"", header.Algorithm)
	}

	ok, err = verifier.Verify(payloadBytes, signatureBytes)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrIncorrectSignature
	}

	var claims BasicClaims
	if err = json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	token := NewToken(header, claims)
	token.signature = signatureBytes
	return token, nil
}
