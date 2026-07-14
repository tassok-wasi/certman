package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

func GetRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: cannot generate rsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetECDSAKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: cannot generate ecdsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetED25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: cannot generate ed25519 key: %v", err)
	}
	return privKey, pubKey, nil
}

func ParseKey(privKey, pubKey []byte) (any, any, error) {
	parsedPub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: cannot parse PKIX public key: %w", err)
	}

	if parsedPriv, err := x509.ParsePKCS8PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParsePKCS1PrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}
	if parsedPriv, err := x509.ParseECPrivateKey(privKey); err == nil {
		return parsedPriv, parsedPub, nil
	}

	return nil, nil, errors.New("Error: unknown key type")
}
