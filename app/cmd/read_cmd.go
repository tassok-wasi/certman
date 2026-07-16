package cmd

import (
	"certman/app/utils"
	"encoding/pem"
	"fmt"
	"strings"
)

type ReadCmd struct {
	Cert ReadCertCmd `cmd:"" help:"Reads Certificate from file location and prints it to stdout"`
	Key  ReadKeyCmd  `cmd:"" help:"Reads Key from file location and prints it to stdout"`
}

type ReadCertCmd struct {
	Path string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert) format."`
}

func (rcc *ReadCertCmd) Run() error {
	fullPath, err := utils.JoinHomeDir(rcc.Path)
	if err != nil {
		return err
	}
	cert, err := utils.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("file does not contains valid certificate")
	}

	fmt.Println(string(cert))
	return nil
}

type ReadKeyCmd struct {
	Path    string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.key,.pem) format."`
	Decrypt bool   `name:"decrypt" help:"Decrypt the Private key if it is stored as encrypted pem block."`
}

func (rkc *ReadKeyCmd) Run() error {
	fullPath, err := utils.JoinHomeDir(rkc.Path)
	if err != nil {
		return err
	}
	fileBytes, err := utils.ReadFile(fullPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return fmt.Errorf("file %s does not contains valid PEM encoded key", rkc.Path)
	}

	if rkc.Decrypt {
		masterKey, err := utils.GetMasterKey()
		if err != nil {
			return err
		}
		decryptedKey, err := utils.Decrypt(block.Bytes, masterKey)
		if err != nil {
			return err
		}

		pemType := strings.TrimPrefix(block.Type, "ENCRYPTED ")

		finalPem := pem.EncodeToMemory(&pem.Block{
			Type:  pemType,
			Bytes: decryptedKey,
		})

		fmt.Println(string(finalPem))
		return nil
	}

	fmt.Println(string(fileBytes))
	return nil
}
