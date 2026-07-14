package utils

import (
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("Error: unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("Warning: Skipping invalid IP string: %s\n", netIP)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() *big.Int {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		log.Fatalf("Error: cannot generate serial number: %v", err)
	}
	return sNum
}

func JoinHomeDir(filePath string) string {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error: cannot get home directory: %v", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath
	}
	return filePath
}

func GetSqlite() *sql.DB {
	conn, err := sql.Open("sqlite", "certman.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatalf("Error: cannot open database: %v", err)
	}
	return conn
}
