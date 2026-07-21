package csr

import (
	"certman/app/domain"
	"certman/app/utils"
	_db_ "certman/db"
	"certman/db/base"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"log"
)

type GenerateCmd struct {
	CommonName         string   `name:"cn" required:"" help:"Common Name of the Certificate."`
	Country            []string `name:"country" short:"c" help:"Country names of the Certificate."`
	Organization       []string `name:"org" short:"o" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"ou" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" short:"l" help:"Locality names of the Certificate."`
	Province           []string `name:"st" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"addr" help:"StreetAddress names of the Certificate."`
	PostalCode         []string `name:"zip" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"algo" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"Key algorithm used to create the keys and sign the Certificate."`
	DNSNames           []string `name:"dns" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email" help:"EmailAddresses of the Certificate."`
	IPAddresses        []string `name:"ip" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uri" help:"URIs of the Certificate."`
}

func (gc *GenerateCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	keyPair, err := domain.GetKey(domain.KeyType(gc.KeyType))
	if err != nil {
		return err
	}

	signatureAlgo, err := utils.GetSignatureAlgorithm(gc.KeyType)
	if err != nil {
		return err
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            gc.Country,
			Organization:       gc.Organization,
			OrganizationalUnit: gc.OrganizationalUnit,
			Locality:           gc.Locality,
			Province:           gc.Province,
			StreetAddress:      gc.StreetAddress,
			PostalCode:         gc.PostalCode,
			CommonName:         gc.CommonName,
		},
		DNSNames:       gc.DNSNames,
		EmailAddresses: gc.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(gc.IPAddresses),
		URIs:           utils.ToURLs(gc.URIs),

		SignatureAlgorithm: signatureAlgo,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPem, err := utils.EncodeToPem(csr, "CERTIFICATE REQUEST")
	if err != nil {
		return err
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	privBlobPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		key, err := txQuerier.CreateKeyPair(ctx, base.CreateKeyPairParams{
			Name:          utils.GenerateKeyName(gc.CommonName),
			Algorithm:     gc.KeyType,
			PrivateKeyPem: privBlobPem,
			PublicKeyPem:  pubPem,
		})
		if err != nil {
			return fmt.Errorf("failed to create Key Pair in the database: %w", err)
		}

		_, err = txQuerier.CreateCSR(ctx, base.CreateCSRParams{
			CommonName:              csrTemplate.Subject.CommonName,
			KeyName:                 key.Name,
			Status:                  "PENDING",
			CsrPem:                  string(csrPem),
			CertificateSerialNumber: sql.NullString{String: "", Valid: false},
		})
		if err != nil {
			return fmt.Errorf("failed to create CSR in the database: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Success: successfully Created Certificate Signing Request.")

	return nil
}
