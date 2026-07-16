package cmd

import (
	"certman/app/utils"
	"fmt"
	"os"
	"path/filepath"
)

type WriteCmd struct {
	CA      CACmd      `cmd:"" help:"Generates CA Certificate."`
	ICA     InterCACmd `cmd:"" help:"Generates Intermediate CA Certificate."`
	Leaf    LeafCmd    `cmd:"" help:"Generates Leaf Certificate."`
	Force   bool       `name:"force" short:"f" help:"Overwrite the certificate and key files if they already exist."`
	Encrypt bool       `name:"encrypt" short:"e" help:"Encrypt the private key using the master key from your secure OS Keyring."`
}

func (wc *WriteCmd) Run(registry *DataRegistry) error {
	subName := utils.ToSnakeCase(registry.Certificate.Subject.CommonName)
	issName := utils.ToSnakeCase(registry.Certificate.Issuer.CommonName)

	var dir string
	var err error

	// Determine deterministic path based on type
	if registry.Certificate.IsCA && subName == issName {
		baseDir, err := utils.JoinHomeDir("~/certman/certificates/roots")
		if err != nil {
			return err
		}
		dir = filepath.Join(baseDir, subName)
	} else {
		baseDir, err := utils.JoinHomeDir("~/certman/certificates/issued_by")
		if err != nil {
			return err
		}
		dir = filepath.Join(baseDir, issName, subName)
	}

	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return fmt.Errorf("failed to create target certificate directory: %w", err)
	}

	certFilePath := filepath.Join(dir, subName+".cert")
	privKeyFilePath := filepath.Join(dir, subName+"_private_key.pem")
	pubKeyFilePath := filepath.Join(dir, subName+"_public_key.pem")

	if !wc.Force {
		if _, err := os.Stat(certFilePath); err == nil {
			return fmt.Errorf("file already exists at %s; use --force to overwrite", certFilePath)
		}
		if _, err := os.Stat(privKeyFilePath); err == nil {
			return fmt.Errorf("private key already exists at %s; use --force to overwrite", privKeyFilePath)
		}
	}

	useCipher := false
	if wc.Encrypt {
		useCipher = true
	}
	if err := utils.WriteCert(certFilePath, registry.Certificate.Raw); err != nil {
		return fmt.Errorf("failed writing cert: %w", err)
	}
	if err := utils.WriteKey(privKeyFilePath, registry.PrivateKey, utils.PRIVATE, true, true, useCipher); err != nil {
		return fmt.Errorf("failed writing private key: %w", err)
	}
	if err := utils.WriteKey(pubKeyFilePath, registry.PublicKey, utils.PUBLIC, false, true, false); err != nil {
		return fmt.Errorf("failed writing public key: %w", err)
	}

	if !registry.Certificate.IsCA || subName != issName {
		parentCertPath := ""
		if wc.Leaf.ParentCertPath != "" {
			parentCertPath = wc.Leaf.ParentCertPath
		} else if wc.ICA.ParentCertPath != "" {
			parentCertPath = wc.ICA.ParentCertPath
		}

		if parentCertPath != "" {
			parentPEM, err := utils.ReadFile(parentCertPath)
			if err == nil {
				leafPEM := utils.ToPem(registry.Certificate.Raw, "CERTIFICATE")
				fullChainBytes := append(leafPEM, parentPEM...)

				fullChainPath := filepath.Join(dir, subName+"_fullchain.pem")
				if err := os.WriteFile(fullChainPath, fullChainBytes, 0o644); err != nil {
					return fmt.Errorf("failed writing fullchain bundle: %w", err)
				}
			}
		}
	}

	return nil
}
