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

func ParseDefault(data string) (*Token[*BasicHeader, BasicClaims], error) {
	return Parse[*BasicHeader, BasicClaims](data)
}

// Parse returns Token parsed from string or error if some troubles occurred
func Parse[H Header, C Claims](text string) (*Token[H, C], error) {
	data := []byte(text)
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

	var header H
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if typ := header.GetType(); typ != JsonWebTokenType {
		return nil, fmt.Errorf("token type \"%s\" not supported", typ)
	}

	algorithm := header.GetAlgorithm()
	verifier, ok := verifiers[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm \"%s\"", algorithm)
	}

	ok, err = verifier.Verify(payloadBytes, signatureBytes)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrIncorrectSignature
	}

	var claims C
	if err = json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	return NewToken(header, claims), nil
}
