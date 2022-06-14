package alg

// NoneAlgorithm is None algorithm
type NoneAlgorithm struct{}

// Size returns 0 cause signature is empty
func (s NoneAlgorithm) Size() int {
	return 0
}

// Sign returns nil as signature
func (s NoneAlgorithm) Sign(payload []byte) ([]byte, error) {
	return nil, nil
}

// Verify always returns true
func (s NoneAlgorithm) Verify(payload, signature []byte) (bool, error) {
	return true, nil
}
