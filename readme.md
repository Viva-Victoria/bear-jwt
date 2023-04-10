# BEAR JWT 
[![Go](https://github.com/Viva-Victoria/bear-jwt/actions/workflows/go.yaml/badge.svg)](https://github.com/Viva-Victoria/bear-jwt/actions/workflows/go.yaml)
[![codecov](https://codecov.io/gh/Viva-Victoria/bear-jwt/branch/master/graph/badge.svg?token=IelspWAvBc)](https://codecov.io/gh/Viva-Victoria/bear-jwt)

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
- 100% **golang** library
- **EdDSA** implementation
- full **RFC 7515, 7517, 7518** compliance
- ~90% test coverage
- lightweight and simple

### Install
`go get github.com/Viva-Victoria/bear-jwt`

### Example
Create new token:
```golang
func init() {
	hs256, err := alg.NewHmacSha(alg.HS256, "your secret")
	if err != nil {
		panic(err)
	}
	jwt.Register(alg.HS256, hs256, hs256)
}

func newToken(userId string) (string, error) {
    token := jwt.NewToken[*jwt.BasicHeader, BasicClaims](
		jwt.NewBasicHeader(alg.HS256), 
		jwt.BasicClaims{
		    Id: uuid.NewString(),
		    IssuedAt: jwt.PosixNow(),
        },
    )
    
    return token.WriteString()
}
```
You can add key info to Header (RFC 7517):
```golang
token := jwt.NewToken(alg.HS256)
token.GetHeader().SetKeyId(1)
```

Parsing token:
```golang
func parseUserId(httpHeader string) (string, error) {
    hs256 := alg.NewSha256("server-secret")
    Register(HS256, hs256, hs256)
    
    token, err := Parse[*jwt.BasicHeader, myClaims](strings.Replace(httpHeader, "Bearer ", ""))
    if err != nil {
        return "", err
    }
	
    // check issued_at, expires and not_before
    state := token.Validate()
    if state != jwt.StateValid {
        return "", fmt.Errorf("bad token: %d", state)
    }
	
    return token.GetClaims().UserId, nil
}
```

### Docs 
Coming soon

### Contribution
Coming soon
