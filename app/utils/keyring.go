package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in Fedora's keyring
func InitMasterKey() {
	// Check if a key already exists to prevent accidental overwriting
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		log.Fatal("Error: application is already initialized with a master key")
	}

	// Generate a secure 32-byte (256-bit) AES key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Fatalf("Error: cannot generate secure bytes: %v", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	// Save to OS Keyring
	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		log.Fatalf("Error: cannot store key in OS keyring: %v", err)
	}
}

// GetMasterKey silently retrieves the key from the OS keyring for cryptography
func GetMasterKey() []byte {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			log.Fatal("Error: app not initialized. Please run the init command first")
			return nil
		}
		log.Fatalf("Error: cannot fetch key from OS keyring: %v", err)
		return nil
	}

	// Decode back to raw bytes for AES-GCM encryption/decryption
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return keyBytes
}
