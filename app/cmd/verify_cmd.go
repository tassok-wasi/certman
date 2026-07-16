package cmd

import (
	"certman/app/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"
)

type VerifyCmd struct {
	Cert VerifyCertCmd `cmd:"" help:"Verify Certificate."`
	Key  VerifyKeyCmd  `cmd:"" help:"Verify Key Pair with Certificate."`
}

type VerifyCertCmd struct {
	Path    string `name:"path" short:"p" type:"path" required:"" help:"Path of the Certificate that needs to be verified."`
	Issuer  string `name:"issuer" short:"i" type:"path" required:"" help:"Path of the Issuer Certificate that will be used to verify the Certificate."`
	Root    string `name:"root" short:"r" type:"path" help:"Path of the Root Certificate. If Issuer is an Intermediate then this Root path is needed."`
	DNSName string `name:"dns-name" short:"d" help:"Optional DNS Name (e.g., 'example.com') to verify the certificate's SAN or Common Name."`
}

func (vc *VerifyCertCmd) Run() error {
	certFullPath, err := utils.JoinHomeDir(vc.Path)
	if err != nil {
		return err
	}
	cert, err := utils.ReadCert(certFullPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// 1. Basic Expiry Check & Warnings
	now := time.Now()
	if now.Before(cert.NotBefore) {
		log.Printf("Warning: Certificate is not valid yet! (Starts: %s)\n", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		log.Printf("Warning: Certificate is EXPIRED! (Expired on: %s)\n", cert.NotAfter.Format(time.RFC3339))
	} else if cert.NotAfter.Sub(now) < (30 * 24 * time.Hour) {
		daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
		log.Printf("Warning: Certificate expires soon in %d days! (Expires on: %s)\n", daysRemaining, cert.NotAfter.Format(time.RFC3339))
	}

	issuerFullPath, err := utils.JoinHomeDir(vc.Issuer)
	if err != nil {
		return err
	}
	issuerCert, err := utils.ReadCert(issuerFullPath)
	if err != nil {
		return fmt.Errorf("failed to read issuer certificate: %w", err)
	}

	rootPool := x509.NewCertPool()
	intermediatesPool := x509.NewCertPool()

	isRoot := issuerCert.CheckSignatureFrom(issuerCert) == nil

	if isRoot {
		rootPool.AddCert(issuerCert)
	} else {
		intermediatesPool.AddCert(issuerCert)

		if vc.Root == "" {
			return errors.New("the provided issuer is an intermediate certificate; you must provide the --root path to verify the chain of trust")
		}

		rootFullPath, err := utils.JoinHomeDir(vc.Root)
		if err != nil {
			return nil
		}
		rootCert, err := utils.ReadCert(rootFullPath)
		if err != nil {
			return fmt.Errorf("failed to read root certificate: %w", err)
		}
		rootPool.AddCert(rootCert)
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatesPool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if vc.DNSName != "" {
		opts.DNSName = vc.DNSName
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	log.Println("Success: Certificate chain is valid and trusted!")
	log.Printf("Verified Chain depth: %d certificates in the trust chain.\n", len(chains[0]))
	return nil
}

type VerifyKeyCmd struct {
	Cert    string `name:"cert" short:"c" type:"path" required:"" help:"Path of the Certificate of which key will be verified."`
	Key     string `name:"key" short:"k" type:"path" required:"" help:"Path of the Private Key file that needs to be verified."`
	Decrypt bool   `name:"decrypt" help:"Decrypt the Private key if it is stored as encrypted pem block."`
}

func (vc *VerifyKeyCmd) Run() error {
	certFullPath, err := utils.JoinHomeDir(vc.Cert)
	if err != nil {
		return err
	}
	cert, err := utils.ReadCert(certFullPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	usedCipher := false
	if vc.Decrypt {
		usedCipher = true
	}
	privateKeyFullPath, err := utils.JoinHomeDir(vc.Key)
	if err != nil {
		return err
	}
	privateKey, err := utils.ReadKey(privateKeyFullPath, usedCipher)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an RSA public key, but the private key is not RSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: RSA private key does not belong to this certificate")
		}

	case *ecdsa.PublicKey:
		priv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an ECDSA public key, but the private key is not ECDSA")
		}
		if !pub.Equal(&priv.PublicKey) {
			return errors.New("cryptographic mismatch: ECDSA private key does not belong to this certificate")
		}

	case ed25519.PublicKey:
		priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return errors.New("key mismatch: certificate holds an Ed25519 public key, but the private key is not Ed25519")
		}
		privPub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || !pub.Equal(privPub) {
			return errors.New("cryptographic mismatch: Ed25519 private key does not belong to this certificate")
		}

	default:
		return fmt.Errorf("unsupported public key algorithm type: %T", cert.PublicKey)
	}

	log.Println("Success: The private key perfectly matches the certificate public key.")
	return nil
}
