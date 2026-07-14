package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

type KeyType int

const (
	PUBLIC KeyType = iota
	PRIVATE
)

// WriteCert saves the certificate bytes into a standard PEM encoded certificate file
// filePath can be linux path, relative path, absolute path or just file name
func WriteCert(filePath string, certBytes []byte) {
	// Certificates are public data, standard 0644 permissions are fine
	write(filePath, "CERTIFICATE", certBytes, 0o644)
}

// WriteKey takes a concrete key (e.g., *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
// and dynamically handles legacy or PKCS#8 formatting.
func WriteKey(filePath string, key any, keyType KeyType, usePKCS8 bool) {
	if keyType == PUBLIC {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			log.Fatalf("Error: cannot marshal public key: %v", err)
		}
		write(filePath, "PUBLIC KEY", pubBytes, 0o644)
		return
	}

	// For PRIVATE keys:
	var blockType string
	var privBytes []byte
	var err error

	if usePKCS8 {
		blockType = "PRIVATE KEY"
		privBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			log.Fatalf("Error: cannot marshal to PKCS#8: %v", err)
		}
	} else {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blockType = "RSA PRIVATE KEY"
			privBytes = x509.MarshalPKCS1PrivateKey(k)
		case *ecdsa.PrivateKey:
			blockType = "EC PRIVATE KEY"
			privBytes, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				log.Fatalf("Error: cannot marshal EC key: %v", err)
			}
		default:
			blockType = "PRIVATE KEY"
			privBytes, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				log.Fatalf("Error: cannot marshal to PKCS#8: %v", err)
			}
		}
	}

	write(filePath, blockType, privBytes, 0o600)
}

// write is a generic helper to write PEM blocks to disk
func write(filePath string, blockType string, bytes []byte, perm os.FileMode) {
	path := JoinHomeDir(filePath)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		log.Fatalf("Error: cannot open %s for writing: %v", path, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
	if err != nil {
		log.Fatalf("Error: cannot write to the file : %v", err)
	}

	log.Printf("Success: successfully created %s\n", path)
}
