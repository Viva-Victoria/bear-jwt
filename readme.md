# BEAR JWT 
[![Build Status](https://app.travis-ci.com/Viva-Victoria/bear-jwt.svg?branch=dev)](https://app.travis-ci.com/Viva-Victoria/bear-jwt) [![codecov](https://codecov.io/gh/Viva-Victoria/bear-jwt/branch/dev/graph/badge.svg?token=6HV6WADQGC)](https://codecov.io/gh/Viva-Victoria/bear-jwt)
### bear-jwt is a part of big web api framework BEAR
Simple tool for parsing and creating json web tokens. 

### Signature  
Implemented all well-known algorithms:  
- HMAC SHA 256 / 384 / 512,  
- RSA 256 / 384 / 512,  
- ECDSA 256 / 384 / 512,  
- RSA-PSS 256 / 384 / 512,  
- EdDSA (ed25519)  
Open api with simple interfaces `Signer` and `Verifier` allows you to extend this list and
implement any other algorithm.

### Features
- 100% **pure golang** library
- **EdDSA** implementation
- full **RFC 7515, 7517, 7518** compliance
- ~70% test coverage
- lightweight and simple

### Install
`go get github.com/Viva-Victoria/bear-jwt`

### Example
Create new token:
```golang
func newToken(userId string) (string, error) {
    token := Token{
        Header: Header{
            Algorithm: None,
            Type:      JsonWebTokenType,
        },
        signer: alg.NewSha256("server-secret"),
    }
    return token.Write(myClaims{
	    Expires: time.Now().Add(time.Hour*24),
		UserId: userId
    })
}
```
You can add key info to Header (RFC 7517):
```golang
Header{
    Algorithm: None,
    Type:      JsonWebTokenType,
    KeyId:     "1",
},
```

Parsing token:
```golang
func parseUserId(httpHeader string) (string, error) {
    parser := NewParser()
	
    hs256 := alg.NewSha256("server-secret")
    parser.Register(HS256, hs256, hs256)
    
    token, err := parser.Parse(strings.Replace(httpHeader, "Bearer ", ""))
    if err != nil {
        return "", err
    }
	
	// check issued_at, expires and not_before
	err = token.Validate()
	if err != nil {
		return "", err
    }
	
    var info myClaims
    if err = token.UnmarshalClaims(&info); err != nil {
        return "", err
    }
	
    return info.UserId, nil
}
```

### Docs 
Coming soon

### Contribution
Coming soon