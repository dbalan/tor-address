package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"strings"
)

func main() {
	fmt.Println("hello world")
}

func computePubKey(priv string) (*rsa.PublicKey, error) {
	block, buf := pem.Decode([]byte(priv))
	if len(buf) > 0 {
		return nil, fmt.Errorf("multiple blocks in pem?")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

func ComputeAddr(priv string) (string, error) {
	pubKey, err := computePubKey(priv)
	if err != nil {
		return "", err
	}

	// marshal key into DER
	pubder := x509.MarshalPKCS1PublicKey(pubKey)

	// tor magic
	return computeTorAddress(pubder), nil
}

func computeTorAddress(pubder []byte) string {
	hs := sha1.New()
	hs.Write(pubder)
	hashed := hs.Sum(nil)

	// we only care about first 10 bytes
	hashed = hashed[:10]

	addr := base32.StdEncoding.EncodeToString(hashed)
	return fmt.Sprintf("%s.onion", strings.ToLower(addr))
}
