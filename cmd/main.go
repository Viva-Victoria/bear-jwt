package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
)

func main() {
	var (
		alg string
	)

	flag.StringVar(&alg, "alg", "", "Algorithm: ed25519")
	flag.Parse()

	switch alg {
	case "ed25519":
		genEd25519()
	case "ecdsa":
		genECDSA()
	case "pkcs":
		genPKCS()
	}
}

func genEd25519() {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	log.Printf("public: %s\nprivate: %s", toBase64(public), toBase64(private))
}

func genECDSA() {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)

		x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

		x509EncodedPub, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
		pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

		log.Printf("%d:\n\tprivate: %s\n\tpublic: %s\n", curve.Params().BitSize, string(pemEncoded), string(pemEncodedPub))
	}
}

func genPKCS() {
	for _, bits := range []int{1024, 2048, 4096} {
		privateKey, _ := rsa.GenerateKey(rand.Reader, bits)

		x509Encoded := x509.MarshalPKCS1PrivateKey(privateKey)
		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

		x509EncodedPub, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
		pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

		log.Printf("%d:\n\tprivate: %s\n\tpublic: %s\n", bits, string(pemEncoded), string(pemEncodedPub))
	}
}

func toBase64(d []byte) string {
	return base64.RawURLEncoding.EncodeToString(d)
}
