package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	if len(os.Args[1:]) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s <path-to-priv.pem>\n", os.Args[0])
		os.Exit(-1)
	}

	filePath := os.Args[1]
	pem, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(-1)
	}

	addr, err := ComputeAddr(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(-1)
	}

	fmt.Printf("tor address: %s\n", addr)
}

func ComputeAddr(priv []byte) (string, error) {
	pubKey, err := computePubKey(priv)
	if err != nil {
		return "", err
	}

	// marshal key into DER
	pubder := x509.MarshalPKCS1PublicKey(pubKey)

	// tor magic
	return computeTorAddress(pubder), nil
}

func computePubKey(priv []byte) (*rsa.PublicKey, error) {
	block, buf := pem.Decode(priv)
	if len(buf) > 0 {
		return nil, fmt.Errorf("multiple blocks in pem?")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
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
