package jwt

import "errors"

type Type string

const (
	JsonWebTokenType Type = "JWT"
)

var (
	ErrNoData             = errors.New("no data")
	ErrIncorrectFormat    = errors.New("incorrect format")
	ErrIncorrectSignature = errors.New("incorrect signature")
	ErrExpired            = errors.New("token expired")
	ErrInactive           = errors.New("token inactive")
	ErrNotIssued          = errors.New("token yet not issued")
)
