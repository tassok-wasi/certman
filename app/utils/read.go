package utils

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func ReadFile(filePath string) []byte {
	path := JoinHomeDir(filePath)

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error: cannot read file data: %v", err)
	}

	return fileBytes
}

// ReadCert reads file and returns the x509.Certificate formatted cert
// filePath can be linux path, relative path, absolute path or just file name
func ReadCert(filePath string) *x509.Certificate {
	fileBytes := ReadFile(filePath)

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		log.Fatalf("Error: file %s does not contain PEM block", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Error: cannot parse cert: %v", err)
	}

	return cert
}

// ReadKey reads file and returns the pkcs#8 for private key and pkix for public key
// filePath can be linux path, relative path, absolute path or just file name
func ReadKey(filePath string) any {
	fileBytes := ReadFile(filePath)

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		log.Fatalf("Error: file %s does not contain PEM block", filePath)
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key
	}

	log.Fatalf("Error: file %v does not contain valid private or public key", filePath)
	return nil
}
