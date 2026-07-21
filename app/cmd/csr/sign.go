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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"
)

type SignCmd struct {
	ID   int64  `arg:"" help:"ID of the CSR to Sign."`
	Type string `name:"type" required:"" help:"Type of the Certificate e.g., CA, INTERMEDIATE, LEAF"`
	TTL  string `name:"ttl" short:"t" required:"" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`

	KeyUsages    []string `name:"ku" enum:"digital-signature,content-commitment,key-encipherment,data-encipherment,key-agreement,cert-sign,crl-sign,encipher-only,decipher-only" help:"Custom key usages (comma-separated or multiple flags)."`
	ExtKeyUsages []string `name:"eku" enum:"any,server-auth,client-auth,code-signing,email-protection,time-stamping,ocsp-signing" help:"Custom extended key usages (comma-separated or multiple flags)."`

	IssuerID int64 `name:"id" help:"Issuer Certificate ID"`
}

func (sc *SignCmd) Run(ctx context.Context, db *sql.DB, query base.Querier) error {
	hours, err := utils.ParseTTLToHours(sc.TTL)
	if err != nil {
		return fmt.Errorf("invalid entry for --ttl/-t: %v", err)
	}

	dbCsr, err := query.GetCSRByID(ctx, sc.ID)
	if err != nil {
		return fmt.Errorf("failed to get CSR from db: %w", err)
	}

	csrBlock, _ := pem.Decode([]byte(dbCsr.CsrPem))
	if csrBlock == nil {
		return errors.New("could not decode CSR pem block")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	issuerDBCert, err := query.GetCertificateByID(ctx, int64(sc.IssuerID))
	if err != nil {
		return fmt.Errorf("failed to get Certificate from db: %w", err)
	}
	issuerKeysDB, err := query.GetKeyByName(ctx, issuerDBCert.KeyName)
	if err != nil {
		return fmt.Errorf("failed to get issuer keys from db: %w", err)
	}

	issuerCert, err := utils.ParseCertificate([]byte(issuerDBCert.CertificatePem))
	if err != nil {
		return err
	}
	issuerPrivKey, issuerPubKey, err := utils.ParseKeys([]byte(issuerKeysDB.PrivateKeyPem), []byte(issuerKeysDB.PublicKeyPem))
	if err != nil {
		return err
	}

	isCa := false
	if sc.Type == "CA" || sc.Type == "INTERMEDIATE" {
		isCa = true
	}

	usages := domain.KeyUsageConfig{
		KeyUsages:    utils.ParseKeyUsages(sc.KeyUsages),
		ExtKeyUsages: utils.ParseExtKeyUsages(sc.ExtKeyUsages),
	}

	template, err := sc.getTemplate(csr.Subject, domain.SANs{
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}, hours, issuerPubKey, issuerCert.SubjectKeyId, isCa, &usages)

	certBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, csr.PublicKey, issuerPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// ------------------------------ WRITING TO THE DATABASE ------------------------------

	certPemBytes, err := utils.EncodeToPem(certBytes, "CERTIFICATE")
	if err != nil {
		return err
	}

	err = _db_.RunInTx(ctx, db, func(txQuerier base.Querier) error {
		_, err = txQuerier.CreateCertificate(ctx, base.CreateCertificateParams{
			SerialNumber:       cert.SerialNumber.String(),
			CommonName:         cert.Subject.CommonName,
			Type:               sc.Type,
			KeyName:            dbCsr.KeyName,
			IssuerSerialNumber: sql.NullString{String: issuerCert.SerialNumber.String(), Valid: true},
			Skid:               hex.EncodeToString(cert.SubjectKeyId),
			Akid:               hex.EncodeToString(cert.AuthorityKeyId),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			CertificatePem:     certPemBytes,
		})
		if err != nil {
			return fmt.Errorf("failed to create Certificate in the database: %w", err)
		}

		err = txQuerier.UpdateCSRStatus(ctx, base.UpdateCSRStatusParams{
			Status:                  "SIGNED",
			CertificateSerialNumber: sql.NullString{String: cert.SerialNumber.String(), Valid: true},
			CommonName:              dbCsr.CommonName,
		})
		if err != nil {
			return fmt.Errorf("failed to update csr status: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("transaction failed, data rolled back: %w", err)
	}

	log.Println("Succes: successfully created Certificate.")

	return nil
}

func (sc *SignCmd) getTemplate(subject pkix.Name, san domain.SANs, hours int, PublicKey any, akid []byte, isCa bool, usages *domain.KeyUsageConfig) (*x509.Certificate, error) {
	skid, err := domain.GenerateSKID(PublicKey)
	if err != nil {
		return nil, err
	}

	sNum, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:   sNum,
		Subject:        subject,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Duration(hours) * time.Hour),
		SubjectKeyId:   skid,
		AuthorityKeyId: akid,

		DNSNames:       san.DNSNames,
		EmailAddresses: san.EmailAddresses,
		IPAddresses:    san.IPAddresses,
		URIs:           san.URIs,

		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}

	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		if isCa {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}

	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	return &template, nil
}
