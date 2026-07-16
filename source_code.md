# Code documentation for `certman`

*Generated from: `/home/tassok/CLI/certman`*

**Extensions included:** .go

---

## `app/cmd/ca_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/ca_cmd.go`
- **Size:** 6410 bytes

```go
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"

	"charm.land/huh/v2"
)

type CACmd struct {
	CommonName         string   `name:"common-name" help:"Common Name of the Certificate."`
	Country            []string `name:"country" help:"Country names of the Certificate."`
	Organization       []string `name:"org" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"province" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"post" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"key-type specifies the Key will be used to sign the Certificate."`
	TTL                string   `name:"ttl" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"86400h"`
	IT                 bool     `name:"it" help:"Bypass the flags and provide input via interactive prompt"`

	KeyUsages []string `name:"key-usage" help:"Custom key usages (comma-separated or multiple flags). e.g: cert-sign, crl-sign"`
}

func CAPrompt(initial *CACmd) (*CACmd, error) {
	var (
		cn         = initial.CommonName
		countries  = strings.Join(initial.Country, ", ")
		orgs       = strings.Join(initial.Organization, ", ")
		units      = strings.Join(initial.OrganizationalUnit, ", ")
		localities = strings.Join(initial.Locality, ", ")
		provinces  = strings.Join(initial.Province, ", ")
		streets    = strings.Join(initial.StreetAddress, ", ")
		posts      = strings.Join(initial.PostalCode, ", ")
		keyType    = initial.KeyType
		ttlStr     string

		keyUsages = initial.KeyUsages
	)

	if len(keyUsages) == 0 {
		keyUsages = []string{"cert-sign", "crl-sign"}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Common Name").Value(&cn).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("common name cannot be left blank")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("Key Type").
				Options(
					huh.NewOption("RSA 2048", "rsa-2048"),
					huh.NewOption("RSA 4096", "rsa-4096"),
					huh.NewOption("ECDSA 224", "ecdsa-224"),
					huh.NewOption("ECDSA 256", "ecdsa-256"),
					huh.NewOption("ECDSA 384", "ecdsa-384"),
					huh.NewOption("ECDSA 521", "ecdsa-521"),
					huh.NewOption("Ed25519", "ed25519"),
				).Value(&keyType),
			huh.NewInput().Title("TTL (Time To Live)").
				Description("Specify duration, e.g., 1000h (hours), 30d (days), 10y (years)").
				Value(&ttlStr).Validate(func(str string) error {
				_, err := utils.ParseTTLToHours(str)
				return err
			}),
			huh.NewMultiSelect[string]().
				Title("Allowed Key Usages").
				Description("Choose cryptographic actions this CA is permitted to perform").
				Options(
					huh.NewOption("Certificate Signing (Default)", "cert-sign"),
					huh.NewOption("CRL Signing (Default)", "crl-sign"),
					huh.NewOption("Digital Signature", "digital-signature"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Key Encipherment", "key-encipherment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	parsedTTL, err := utils.ParseTTLToHours(ttlStr)
	if err != nil {
		return nil, err
	}
	return &CACmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		KeyType:            keyType,
		TTL:                strconv.Itoa(parsedTTL),
		IT:                 true,
		KeyUsages:          keyUsages,
	}, nil
}

func (cc *CACmd) Run(registry *DataRegistry) error {
	finalConfig := cc
	if cc.IT {
		promptResult, err := CAPrompt(cc)
		if err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type")
		}
		hours, err := utils.ParseTTLToHours(cc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages: utils.ParseKeyUsages(finalConfig.KeyUsages),
	}

	ttl, err := strconv.Atoi(finalConfig.TTL)
	if err != nil {
		return err
	}
	caCert, err := domain.GetCA(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, ttl, keyPair, usages)
	if err != nil {
		return fmt.Errorf("cannot generate CA Certificate: %w", err)
	}

	registry.Certificate = caCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
```

---

## `app/cmd/init_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/init_cmd.go`
- **Size:** 413 bytes

```go
package cmd

import (
	"certman/app/utils"
	"fmt"
	"os"
)

type InitCmd struct{}

func (ic *InitCmd) Run() error {
	err := utils.InitMasterKey()
	if err != nil {
		return err
	}

	fullPath, err := utils.JoinHomeDir("~/certman/certificates")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(fullPath, 0o755); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}
	return nil
}
```

---

## `app/cmd/inspect_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/inspect_cmd.go`
- **Size:** 12602 bytes

```go
package cmd

import (
	"certman/app/utils"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type InspectCmd struct {
	Cert InspectCertCmd `cmd:"" help:"Prints raw Certificate in stdout."`
	Key  InspectKeyCmd  `cmd:"" help:"Prints raw Key in stdout."`
}

type InspectCertCmd struct {
	Path        string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert) format."`
	Fingerprint bool   `name:"fingerprint" short:"f" help:"Display SHA-1 and SHA-256 fingerprints."`
	Extensions  bool   `name:"extensions" short:"e" help:"Display X.509 structural extension usage flags (Key Usage, CA flags)."`
	JSON        bool   `name:"json" short:"j" help:"Output certificate details in raw JSON format for scripting."`
}

type certJSONOutput struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SerialNumber string   `json:"serial_number"`
	SignatureAlg string   `json:"signature_algorithm"`
	KeyAlgo      string   `json:"key_algorithm"`
	KeySize      string   `json:"key_size"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names,omitempty"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	SHA256       string   `json:"sha256_fingerprint,omitempty"`
}

func (icc *InspectCertCmd) Run() error {
	fullPath, err := utils.JoinHomeDir(icc.Path)
	if err != nil {
		return err
	}
	cert, err := utils.ReadCert(fullPath)
	if err != nil {
		return err
	}

	keyAlgo, keySize := getKeyDetails(cert.PublicKey)

	if icc.JSON {
		out := certJSONOutput{
			Subject:      formatDN(cert.Subject),
			Issuer:       formatDN(cert.Issuer),
			SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			KeyAlgo:      keyAlgo,
			KeySize:      keySize,
			NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05 UTC"),
			NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
			DNSNames:     cert.DNSNames,
		}
		for _, ip := range cert.IPAddresses {
			out.IPAddresses = append(out.IPAddresses, ip.String())
		}
		if icc.Fingerprint {
			sum256 := sha256.Sum256(cert.Raw)
			out.SHA256 = formatFingerprint(sum256[:])
		}
		jsonBytes, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
		return nil
	}

	// --- Default Pretty Print Output ---
	fmt.Println("Certificate Inspection Report")
	fmt.Println(strings.Repeat("─", 50))

	// Print Full Subject Properties
	fmt.Println("  [ Subject Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Subject))
	if cert.Subject.CommonName != "" {
		fmt.Printf("    • Common Name (CN): %s\n", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("    • Organization (O): %s\n", strings.Join(cert.Subject.Organization, ", "))
	}
	if len(cert.Subject.Country) > 0 {
		fmt.Printf("    • Country (C)     : %s\n", strings.Join(cert.Subject.Country, ", "))
	}

	fmt.Println(strings.Repeat("─", 50))

	// Print Full Issuer Properties
	fmt.Println("  [ Issuer / Signer Identity ]")
	fmt.Printf("    • Full DN: %s\n", formatDN(cert.Issuer))

	fmt.Println(strings.Repeat("─", 50))

	// Print Technical & Crypto Metadata
	fmt.Println("  [ Cryptographic Metadata ]")
	fmt.Printf("    • Serial Number: %x\n", cert.SerialNumber)
	fmt.Printf("    • Signature Alg: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("    • Public Key   : %s (%s)\n", keyAlgo, keySize)

	fmt.Println(strings.Repeat("─", 50))

	// Print Lifecycle Timeline
	fmt.Println("  [ Validity Lifecycle ]")
	fmt.Printf("    • Active From  : %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    • Expires On   : %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))

	fmt.Println(strings.Repeat("─", 50))

	// Print Alternative Target Entities if active
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		fmt.Println("  [ Subject Alternative Names (SAN) ]")
		if len(cert.DNSNames) > 0 {
			fmt.Printf("    • DNS Domains  : %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			fmt.Printf("    • IP Addresses : %v\n", cert.IPAddresses)
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --fingerprint flag ---
	if icc.Fingerprint {
		fmt.Println("  [ Certificate Fingerprints ]")
		sum1 := sha1.Sum(cert.Raw)
		sum256 := sha256.Sum256(cert.Raw)
		fmt.Printf("    • SHA-1  : %s\n", formatFingerprint(sum1[:]))
		fmt.Printf("    • SHA-256: %s\n", formatFingerprint(sum256[:]))
		fmt.Println(strings.Repeat("─", 50))
	}

	// --- Handle --extensions flag ---
	if icc.Extensions {
		fmt.Println("  [ Key Usage & Extensions ]")
		fmt.Printf("    • Basic Constraints (CA): %t\n", cert.IsCA)

		// Parse Key Usages
		var usages []string
		usageMap := map[x509.KeyUsage]string{
			x509.KeyUsageDigitalSignature:  "Digital Signature",
			x509.KeyUsageContentCommitment: "Content Commitment",
			x509.KeyUsageKeyEncipherment:   "Key Encipherment",
			x509.KeyUsageDataEncipherment:  "Data Encipherment",
			x509.KeyUsageKeyAgreement:      "Key Agreement",
			x509.KeyUsageCertSign:          "Certificate Signing",
			x509.KeyUsageCRLSign:           "CRL Signing",
		}
		for flag, name := range usageMap {
			if cert.KeyUsage&flag != 0 {
				usages = append(usages, name)
			}
		}
		if len(usages) > 0 {
			fmt.Printf("    • Intended Key Usages   : %s\n", strings.Join(usages, ", "))
		} else {
			fmt.Println("    • Intended Key Usages   : None Specified")
		}
		fmt.Println(strings.Repeat("─", 50))
	}

	return nil
}

type InspectKeyCmd struct {
	Path     string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.key,.pem) format."`
	Validate bool   `name:"validate" short:"v" help:"Verify the mathematical integrity and validity of the private key."`
	Decrypt  bool   `name:"decrypt" help:"Decrypt the Private key if it is stored as encrypted pem block."`
}

func (ikc *InspectKeyCmd) Run() error {
	usedCipher := false
	if ikc.Decrypt {
		usedCipher = true
	}
	fullPath, err := utils.JoinHomeDir(ikc.Path)
	if err != nil {
		return err
	}
	key, blockType, err := utils.ReturnKeyWithBlockType(fullPath, usedCipher)
	if err != nil {
		return err
	}

	fmt.Printf("Key Inspection Report\n")
	fmt.Println(strings.Repeat("─", 55))
	fmt.Printf("  • PEM Block Header Type: %s\n", blockType)

	switch k := key.(type) {

	// ==================== RSA KEY TYPES ====================
	case *rsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))
		fmt.Printf("  • Prime Factor (P) Size : %d bits\n", len(k.Primes[0].Bytes())*8)
		fmt.Printf("  • Prime Factor (Q) Size : %d bits\n", len(k.Primes[1].Bytes())*8)

		// Check internal sanity variables if requested
		if ikc.Validate {
			if err := k.Validate(); err != nil {
				fmt.Printf("  • Validation Status     : Invalid Key! (%s)\n", err.Error())
			} else {
				fmt.Println("  • Validation Status     :  Mathematical Integrity Intact")
			}
		}

	case *rsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : RSA (Rivest–Shamir–Adleman)")
		fmt.Printf("  • Modulus Bit Size     : %d-bit\n", k.Size()*8)
		fmt.Printf("  • Public Exponent (e)   : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  • Modulus (N) Fingerprint: %s...\n", truncateHex(k.N.Bytes()))

	// ==================== ECDSA KEY TYPES ====================
	case *ecdsa.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		fmt.Printf("  • Order Limit (N)       : %s...\n", truncateHex(k.Params().N.Bytes()))
		fmt.Printf("  • Private Scalar D      : [Protected / Hidden in Memory]\n")
		pubBytes, err := k.Bytes()
		if err != nil {
			return err
		}
		fmt.Printf("  • Linked Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

		if ikc.Validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  • Validation Status     :  Curve Point Verification Successful")
			} else {
				fmt.Println("  • Validation Status     : Invalid Key! Point is off the curve.")
			}
		}

	case *ecdsa.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : ECDSA (Elliptic Curve Digital Signature)")
		fmt.Printf("  • Chosen Curve Architecture: %s\n", k.Params().Name)
		pubBytes, err := k.Bytes()
		if err != nil {
			return err
		}
		fmt.Printf("  • Uncompressed Point (X, Y): %s...\n", truncateHex(pubBytes))

		if ikc.Validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  • Validation Status     :  Curve Point Verification Successful")
			} else {
				fmt.Println("  • Validation Status     : Invalid Key! Point is off the curve.")
			}
		}

	// ==================== ED25519 KEY TYPES ====================
	case ed25519.PrivateKey:
		fmt.Println("  • Key Paradigm          : Private (Secret)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Key Seed Payload      : %s...\n", truncateHex(k.Seed()))

		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			return errors.New("failed to assert ed25519 private key")
		}
		fmt.Printf("  • Extracted Public Key  : %s\n", hex.EncodeToString(pub))

	case ed25519.PublicKey:
		fmt.Println("  • Key Paradigm          : Public (Sharable)")
		fmt.Println("  • Cipher Suite          : Ed25519 (Edwards-curve Digital Signature)")
		fmt.Println("  • Parameters            : Twisted Edwards Curve, Curve25519 base")
		fmt.Printf("  • Complete Public Point : %s\n", hex.EncodeToString(k))

	default:
		fmt.Printf("  • Structural Type Unknown: %T\n", k)
	}

	fmt.Println(strings.Repeat("─", 55))
	return nil
}

// Helper formatting functions
func formatDN(name pkix.Name) string {
	var parts []string

	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}
	if len(name.Organization) > 0 {
		parts = append(parts, fmt.Sprintf("O=%s", strings.Join(name.Organization, ", ")))
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, fmt.Sprintf("OU=%s", strings.Join(name.OrganizationalUnit, ", ")))
	}
	if len(name.Country) > 0 {
		parts = append(parts, fmt.Sprintf("C=%s", strings.Join(name.Country, ", ")))
	}
	if len(name.Province) > 0 {
		parts = append(parts, fmt.Sprintf("ST=%s", strings.Join(name.Province, ", ")))
	}
	if len(name.Locality) > 0 {
		parts = append(parts, fmt.Sprintf("L=%s", strings.Join(name.Locality, ", ")))
	}

	if len(parts) == 0 {
		return "Empty Distinguished Name"
	}
	return strings.Join(parts, ", ")
}

func getKeyDetails(key any) (algoType string, sizeInfo string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		algoType = "RSA Private Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PrivateKey:
		algoType = "ECDSA Private Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PrivateKey:
		algoType = "Ed25519 Private Key"
		sizeInfo = "256-bit seed"
	case *rsa.PublicKey:
		algoType = "RSA Public Key"
		sizeInfo = fmt.Sprintf("%d-bit", k.Size()*8)
	case *ecdsa.PublicKey:
		algoType = "ECDSA Public Key"
		sizeInfo = fmt.Sprintf("Curve: %s", k.Params().Name)
	case ed25519.PublicKey:
		algoType = "Ed25519 Public Key"
		sizeInfo = "256-bit"
	default:
		algoType = fmt.Sprintf("Unknown (%T)", key)
		sizeInfo = "N/A"
	}
	return algoType, sizeInfo
}

func truncateHex(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	fullHex := hex.EncodeToString(b)
	if len(fullHex) > 32 {
		return fullHex[:32]
	}
	return fullHex
}

// Formats a byte slice fingerprint into standard double-spaced format (e.g., "AA:BB:CC:...")
func formatFingerprint(b []byte) string {
	var parts []string
	for _, val := range b {
		parts = append(parts, fmt.Sprintf("%02X", val))
	}
	return strings.Join(parts, ":")
}
```

---

## `app/cmd/inter_ca_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/inter_ca_cmd.go`
- **Size:** 10215 bytes

```go
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"

	"charm.land/huh/v2"
)

type InterCACmd struct {
	CommonName         string   `name:"common-name" help:"Common Name of the Certificate."`
	Country            []string `name:"country" help:"Country names of the Certificate."`
	Organization       []string `name:"org" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"province" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"post" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to crear the keys and sign the Certificate."`
	TTL                string   `name:"ttl" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"17280h"`
	DNSNames           []string `name:"dns-names" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email-addrs" help:"EmailAddresses of the Certificate"`
	IPAddresses        []string `name:"ip-addrs" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uris" help:"URIs of the Certificate"`
	IT                 bool     `name:"it" help:"Bypass the flags and provide input via interactive prompt"`

	ParentCertPath    string `name:"parent-cert" required:"" type:"path" help:"Parent Certificate Path for signing the Intermediate Certificate."`
	ParentPrivkeyPath string `name:"parent-priv-key" required:"" type:"path" help:"Parent Private Key for signing the Intermediate Certificate."`
	Decrypt           bool   `name:"decrypt" help:"Decrypt the Parent Private key if it is stored as encrypted pem block."`

	KeyUsages    []string `name:"key-usage" help:"Custom key usages (comma-separated or multiple flags). e.g: cert-sign, crl-sign"`
	ExtKeyUsages []string `name:"ext-key-usage" help:"Custom extended key usages (comma-separated or multiple flags). e.g: server-auth, client-auth"`
}

func InterCAPrompt(initial *InterCACmd) (*InterCACmd, error) {
	var (
		cn             = initial.CommonName
		countries      = strings.Join(initial.Country, ", ")
		orgs           = strings.Join(initial.Organization, ", ")
		units          = strings.Join(initial.OrganizationalUnit, ", ")
		localities     = strings.Join(initial.Locality, ", ")
		provinces      = strings.Join(initial.Province, ", ")
		streets        = strings.Join(initial.StreetAddress, ", ")
		posts          = strings.Join(initial.PostalCode, ", ")
		keyType        = initial.KeyType
		dnsNames       = strings.Join(initial.DNSNames, ", ")
		emailAddresses = strings.Join(initial.EmailAddresses, ", ")
		ipAddresses    = strings.Join(initial.IPAddresses, ", ")
		uris           = strings.Join(initial.URIs, ", ")
		ttlStr         string

		keyUsages    = initial.KeyUsages
		extKeyUsages = initial.ExtKeyUsages
	)

	if len(keyUsages) == 0 {
		keyUsages = []string{"cert-sign", "crl-sign"}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Common Name").Value(&cn).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("common name cannot be left blank")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("Key Type").
				Options(
					huh.NewOption("RSA 2048", "rsa-2048"),
					huh.NewOption("RSA 4096", "rsa-4096"),
					huh.NewOption("ECDSA 224", "ecdsa-224"),
					huh.NewOption("ECDSA 256", "ecdsa-256"),
					huh.NewOption("ECDSA 384", "ecdsa-384"),
					huh.NewOption("ECDSA 521", "ecdsa-521"),
					huh.NewOption("Ed25519", "ed25519"),
				).Value(&keyType),
			huh.NewInput().Title("TTL (Time To Live)").
				Description("Specify duration, e.g., 1000h (hours), 30d (days), 10y (years)").
				Value(&ttlStr).Validate(func(str string) error {
				_, err := utils.ParseTTLToHours(str)
				return err
			}),
			huh.NewMultiSelect[string]().
				Title("Allowed Key Usages").
				Description("Choose cryptographic actions this Intermediate CA is permitted to perform").
				Options(
					huh.NewOption("Certificate Signing (Default)", "cert-sign"),
					huh.NewOption("CRL Signing (Default)", "crl-sign"),
					huh.NewOption("Digital Signature", "digital-signature"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Key Encipherment", "key-encipherment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
			huh.NewMultiSelect[string]().
				Title("Extended Key Usages (Optional)").
				Description("Define specific downstream usage restrictions for this Intermediate CA").
				Options(
					huh.NewOption("Any Purpose", "any"),
					huh.NewOption("Server Authentication", "server-auth"),
					huh.NewOption("Client Authentication", "client-auth"),
					huh.NewOption("Code Signing", "code-signing"),
					huh.NewOption("Email Protection", "email-protection"),
					huh.NewOption("Time Stamping", "time-stamping"),
					huh.NewOption("OCSP Signing", "ocsp-signing"),
				).Value(&extKeyUsages),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
			huh.NewInput().Title("DNS Names (comma separated)").Value(&dnsNames),
			huh.NewInput().Title("Email Addresses (comma separated)").Value(&emailAddresses),
			huh.NewInput().Title("IP Addresses (comma separated)").Value(&ipAddresses),
			huh.NewInput().Title("URIs (comma separated)").Value(&uris),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	parsedTTL, err := utils.ParseTTLToHours(ttlStr)
	if err != nil {
		return nil, err
	}
	return &InterCACmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		DNSNames:           utils.SplitCSV(dnsNames),
		EmailAddresses:     utils.SplitCSV(emailAddresses),
		IPAddresses:        utils.SplitCSV(ipAddresses),
		URIs:               utils.SplitCSV(uris),
		KeyType:            keyType,
		TTL:                strconv.Itoa(parsedTTL),
		IT:                 true,
		KeyUsages:          keyUsages,
		ExtKeyUsages:       extKeyUsages,
		ParentCertPath:     initial.ParentCertPath,
		ParentPrivkeyPath:  initial.ParentPrivkeyPath,
	}, nil
}

func (icc *InterCACmd) Run(registry *DataRegistry) error {
	finalConfig := icc
	if icc.IT {
		promptResult, err := InterCAPrompt(icc)
		if err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type")
		}
		hours, err := utils.ParseTTLToHours(icc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)
		if finalConfig.ParentCertPath == "" {
			return fmt.Errorf("missing required flag: --parent-cert")
		}
		if finalConfig.ParentPrivkeyPath == "" {
			return fmt.Errorf("missing required flag: --parent-priv-key")
		}
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	parentCertFullPath, err := utils.JoinHomeDir(finalConfig.ParentCertPath)
	if err != nil {
		return err
	}
	parentCert, err := utils.ReadCert(parentCertFullPath)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid certificate", finalConfig.ParentCertPath)
	}
	usedCipher := false
	if icc.Decrypt {
		usedCipher = true
	}

	parentPrivKeyFullPath, err := utils.JoinHomeDir(finalConfig.ParentPrivkeyPath)
	if err != nil {
		return err
	}
	parentPrivKey, err := utils.ReadKey(parentPrivKeyFullPath, usedCipher)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid private key", finalConfig.ParentPrivkeyPath)
	}

	parent := domain.Certificate{
		Cert: parentCert,
		Keys: &domain.KeyPair{
			PrivateKey: parentPrivKey,
		},
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages:    utils.ParseKeyUsages(finalConfig.KeyUsages),
		ExtKeyUsages: utils.ParseExtKeyUsages(finalConfig.ExtKeyUsages),
	}

	ttl, err := strconv.Atoi(finalConfig.TTL)
	if err != nil {
		return err
	}
	interCaCert, err := domain.GetIntermediate(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, domain.SANs{
		DNSNames:       finalConfig.DNSNames,
		EmailAddresses: finalConfig.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(finalConfig.IPAddresses),
		URIs:           utils.ToURLs(finalConfig.URIs),
	}, ttl, keyPair, &parent, usages)
	if err != nil {
		return fmt.Errorf("cannot generate Intermediate CA Certificate: %w", err)
	}

	registry.Certificate = interCaCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
```

---

## `app/cmd/leaf_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/leaf_cmd.go`
- **Size:** 10145 bytes

```go
package cmd

import (
	"crypto/x509/pkix"
	"fmt"
	"strconv"
	"strings"

	"certman/app/domain"
	"certman/app/utils"

	"charm.land/huh/v2"
)

type LeafCmd struct {
	CommonName         string   `name:"common-name" help:"Common Name of the Certificate."`
	Country            []string `name:"country" help:"Country names of the Certificate."`
	Organization       []string `name:"org" help:"Organization names of the Certificate."`
	OrganizationalUnit []string `name:"org-unit" help:"OrganizationalUnit names of the Certificate."`
	Locality           []string `name:"locality" help:"Locality names of the Certificate."`
	Province           []string `name:"province" help:"Province names of the Certificate."`
	StreetAddress      []string `name:"street-addrs" help:"StreetAddress names of the Certificate"`
	PostalCode         []string `name:"post" help:"PostalCode of the Certificate."`
	KeyType            string   `name:"key-type" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ecdsa-256" help:"key-type specifies the Key algorithm will be used to crear the keys and sign the Certificate."`
	TTL                string   `name:"ttl" help:"Time-To-Live of the certificate (e.g., 1000h, 30d, 10y)." default:"8760h"`
	DNSNames           []string `name:"dns-names" help:"DNSNames of the Certificate."`
	EmailAddresses     []string `name:"email-addrs" help:"EmailAddresses of the Certificate"`
	IPAddresses        []string `name:"ip-addrs" help:"IPAddresses of the Certificate."`
	URIs               []string `name:"uris" help:"URIs of the Certificate"`
	IT                 bool     `name:"it" help:"Bypass the flags and provide input via interactive prompt"`

	ParentCertPath    string `name:"parent-cert" type:"path" help:"Parent Certificate Path for signing the Intermediate Certificate."`
	ParentPrivkeyPath string `name:"parent-priv-key" type:"path" help:"Parent Private Key for signing the Intermediate Certificate."`
	Decrypt           bool   `name:"decrypt" help:"Decrypt the Parent Private key if it is stored as encrypted pem block."`

	KeyUsages    []string `name:"key-usage" help:"Custom key usages (comma-separated or multiple flags). e.g: digital-signature, key-encipherment"`
	ExtKeyUsages []string `name:"ext-key-usage" help:"Custom extended key usages (comma-separated or multiple flags). e.g: server-auth, client-auth"`
}

func LeafPrompt(initial *LeafCmd) (*LeafCmd, error) {
	var (
		cn             = initial.CommonName
		countries      = strings.Join(initial.Country, ", ")
		orgs           = strings.Join(initial.Organization, ", ")
		units          = strings.Join(initial.OrganizationalUnit, ", ")
		localities     = strings.Join(initial.Locality, ", ")
		provinces      = strings.Join(initial.Province, ", ")
		streets        = strings.Join(initial.StreetAddress, ", ")
		posts          = strings.Join(initial.PostalCode, ", ")
		keyType        = initial.KeyType
		dnsNames       = strings.Join(initial.DNSNames, ", ")
		emailAddresses = strings.Join(initial.EmailAddresses, ", ")
		ipAddresses    = strings.Join(initial.IPAddresses, ", ")
		uris           = strings.Join(initial.URIs, ", ")
		ttlStr         string

		keyUsages    = initial.KeyUsages
		extKeyUsages = initial.ExtKeyUsages
	)

	if len(keyUsages) == 0 {
		keyUsages = []string{"digital-signature", "key-encipherment"}
	}
	if len(extKeyUsages) == 0 {
		extKeyUsages = []string{"server-auth", "client-auth"}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Common Name").Value(&cn).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("common name cannot be left blank")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("Key Type").
				Options(
					huh.NewOption("RSA 2048", "rsa-2048"),
					huh.NewOption("RSA 4096", "rsa-4096"),
					huh.NewOption("ECDSA 224", "ecdsa-224"),
					huh.NewOption("ECDSA 256", "ecdsa-256"),
					huh.NewOption("ECDSA 384", "ecdsa-384"),
					huh.NewOption("ECDSA 521", "ecdsa-521"),
					huh.NewOption("Ed25519", "ed25519"),
				).Value(&keyType),
			huh.NewInput().Title("TTL (Time To Live)").
				Description("Specify duration, e.g., 1000h (hours), 30d (days), 10y (years)").
				Value(&ttlStr).Validate(func(str string) error {
				_, err := utils.ParseTTLToHours(str)
				return err
			}),
			huh.NewMultiSelect[string]().
				Title("Allowed Key Usages").
				Description("Choose cryptographic actions this Leaf certificate is permitted to perform").
				Options(
					huh.NewOption("Digital Signature (Default)", "digital-signature"),
					huh.NewOption("Key Encipherment (Default)", "key-encipherment"),
					huh.NewOption("Content Commitment", "content-commitment"),
					huh.NewOption("Data Encipherment", "data-encipherment"),
					huh.NewOption("Key Agreement", "key-agreement"),
				).Value(&keyUsages),
			huh.NewMultiSelect[string]().
				Title("Extended Key Usages").
				Description("Define validation scopes for this Leaf certificate").
				Options(
					huh.NewOption("Server Authentication (Default)", "server-auth"),
					huh.NewOption("Client Authentication (Default)", "client-auth"),
					huh.NewOption("Code Signing", "code-signing"),
					huh.NewOption("Email Protection", "email-protection"),
					huh.NewOption("Time Stamping", "time-stamping"),
					huh.NewOption("OCSP Signing", "ocsp-signing"),
					huh.NewOption("Any Purpose", "any"),
				).Value(&extKeyUsages),
		),
		huh.NewGroup(
			huh.NewInput().Title("Countries (comma separated)").Value(&countries),
			huh.NewInput().Title("Organizations (comma separated)").Value(&orgs),
			huh.NewInput().Title("Organizational Units (comma separated)").Value(&units),
			huh.NewInput().Title("Localities (comma separated)").Value(&localities),
			huh.NewInput().Title("Provinces (comma separated)").Value(&provinces),
			huh.NewInput().Title("Street Addresses (comma separated)").Value(&streets),
			huh.NewInput().Title("Postal Codes (comma separated)").Value(&posts),
			huh.NewInput().Title("DNS Names (comma separated)").Value(&dnsNames),
			huh.NewInput().Title("Email Addresses (comma separated)").Value(&emailAddresses),
			huh.NewInput().Title("IP Addresses (comma separated)").Value(&ipAddresses),
			huh.NewInput().Title("URIs (comma separated)").Value(&uris),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	parsedTTL, err := utils.ParseTTLToHours(ttlStr)
	if err != nil {
		return nil, err
	}
	return &LeafCmd{
		CommonName:         strings.TrimSpace(cn),
		Country:            utils.SplitCSV(countries),
		Organization:       utils.SplitCSV(orgs),
		OrganizationalUnit: utils.SplitCSV(units),
		Locality:           utils.SplitCSV(localities),
		Province:           utils.SplitCSV(provinces),
		StreetAddress:      utils.SplitCSV(streets),
		PostalCode:         utils.SplitCSV(posts),
		DNSNames:           utils.SplitCSV(dnsNames),
		EmailAddresses:     utils.SplitCSV(emailAddresses),
		IPAddresses:        utils.SplitCSV(ipAddresses),
		URIs:               utils.SplitCSV(uris),
		KeyType:            keyType,
		TTL:                strconv.Itoa(parsedTTL),
		IT:                 true,
		KeyUsages:          keyUsages,
		ExtKeyUsages:       extKeyUsages,
		ParentCertPath:     initial.ParentCertPath,
		ParentPrivkeyPath:  initial.ParentPrivkeyPath,
	}, nil
}

func (lc *LeafCmd) Run(registry *DataRegistry) error {
	finalConfig := lc
	if lc.IT {
		promptResult, err := LeafPrompt(lc)
		if err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
		}
		finalConfig = promptResult
	} else {
		if finalConfig.CommonName == "" {
			return fmt.Errorf("missing required flag: --common-name")
		}
		if finalConfig.KeyType == "" {
			return fmt.Errorf("missing required flag: --key-type")
		}
		hours, err := utils.ParseTTLToHours(lc.TTL)
		if err != nil {
			return fmt.Errorf("invalid entry for --ttl: %v", err)
		}
		finalConfig.TTL = strconv.Itoa(hours)
		if finalConfig.ParentCertPath == "" {
			return fmt.Errorf("missing required flag: --parent-cert")
		}
		if finalConfig.ParentPrivkeyPath == "" {
			return fmt.Errorf("missing required flag: --parent-priv-key")
		}
	}

	keyPair, err := domain.GetKey(domain.KeyType(finalConfig.KeyType))
	if err != nil {
		return fmt.Errorf("unsupported key type: %s", finalConfig.KeyType)
	}

	parentCertFullPath, err := utils.JoinHomeDir(finalConfig.ParentCertPath)
	if err != nil {
		return err
	}
	parentCert, err := utils.ReadCert(parentCertFullPath)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid certificate", finalConfig.ParentCertPath)
	}
	usedCipher := false
	if lc.Decrypt {
		usedCipher = true
	}

	parentPrivKeyFullPath, err := utils.JoinHomeDir(finalConfig.ParentPrivkeyPath)
	if err != nil {
		return err
	}
	parentPrivKey, err := utils.ReadKey(parentPrivKeyFullPath, usedCipher)
	if err != nil {
		return fmt.Errorf("file %s does not contain valid private key", finalConfig.ParentPrivkeyPath)
	}

	parent := domain.Certificate{
		Cert: parentCert,
		Keys: &domain.KeyPair{
			PrivateKey: parentPrivKey,
		},
	}

	usages := &domain.KeyUsageConfig{
		KeyUsages:    utils.ParseKeyUsages(finalConfig.KeyUsages),
		ExtKeyUsages: utils.ParseExtKeyUsages(finalConfig.ExtKeyUsages),
	}

	ttl, err := strconv.Atoi(finalConfig.TTL)
	if err != nil {
		return err
	}
	leafCert, err := domain.GetLeaf(pkix.Name{
		Country:            finalConfig.Country,
		Organization:       finalConfig.Organization,
		OrganizationalUnit: finalConfig.OrganizationalUnit,
		Locality:           finalConfig.Locality,
		Province:           finalConfig.Province,
		StreetAddress:      finalConfig.StreetAddress,
		PostalCode:         finalConfig.PostalCode,
		CommonName:         finalConfig.CommonName,
	}, domain.SANs{
		DNSNames:       finalConfig.DNSNames,
		EmailAddresses: finalConfig.EmailAddresses,
		IPAddresses:    utils.ToNetIPs(finalConfig.IPAddresses),
		URIs:           utils.ToURLs(finalConfig.URIs),
	}, ttl, keyPair, &parent, usages)
	if err != nil {
		return fmt.Errorf("cannot generate Leaf Certificate: %w", err)
	}

	registry.Certificate = leafCert
	registry.PrivateKey = keyPair.PrivateKey
	registry.PublicKey = keyPair.PublicKey
	return nil
}
```

---

## `app/cmd/read_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/read_cmd.go`
- **Size:** 1754 bytes

```go
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
```

---

## `app/cmd/registry.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/registry.go`
- **Size:** 129 bytes

```go
package cmd

import "crypto/x509"

type DataRegistry struct {
	Certificate *x509.Certificate
	PrivateKey  any
	PublicKey   any
}
```

---

## `app/cmd/verify_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/verify_cmd.go`
- **Size:** 5318 bytes

```go
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
```

---

## `app/cmd/write_cmd.go`

- **Full path:** `/home/tassok/CLI/certman/app/cmd/write_cmd.go`
- **Size:** 3087 bytes

```go
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
```

---

## `app/domain/cert.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/cert.go`
- **Size:** 5613 bytes

```go
package domain

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"certman/app/utils"
)

// GetBaseTemplate generates the basic certificate scaffolding.
func GetBaseTemplate(subject pkix.Name, serialNumber *big.Int, ttlInHour int, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(ttlInHour) * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true, // Crucial for CA validation
	}
}

// GetCA generates a root CA certificate with dynamic key usages.
func GetCA(subject pkix.Name, ttlInHour int, keyPair *KeyPair, usages *KeyUsageConfig) (*x509.Certificate, error) {
	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// Apply dynamic key usages or fallback to standard CA defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Apply dynamic extended key usages if provided
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	}

	// Self-signed CA: Subject Key ID and Authority Key ID match
	skid, err := generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = skid
	template.AuthorityKeyId = skid

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	return caCert, nil
}

// GetIntermediate generates an intermediate CA certificate with dynamic key usages.
func GetIntermediate(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate, usages *KeyUsageConfig) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, errors.New("invalid parent certificate: parent must be a valid CA")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, true)

	// MaxPathLen constraints
	template.MaxPathLen = 0
	template.MaxPathLenZero = true // This intermediate can only sign leaf certs, not more CAs

	// Apply dynamic key usages or fallback to standard CA defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Apply dynamic extended key usages if provided
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	}

	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	interBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate intermediate certificate: %w", err)
	}

	interCaCert, err := x509.ParseCertificate(interBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse intermediate certificate: %w", err)
	}

	return interCaCert, nil
}

// GetLeaf generates a leaf certificate with dynamic key usages.
func GetLeaf(subject pkix.Name, san SANs, ttlInHour int, keyPair *KeyPair, parent *Certificate, usages *KeyUsageConfig) (*x509.Certificate, error) {
	if parent == nil || !parent.Cert.IsCA {
		return nil, fmt.Errorf("invalid parent certificate: leaf must be signed by a CA/Intermediate")
	}

	serialNumber, err := utils.GetSerialNumber()
	if err != nil {
		return nil, err
	}

	template := GetBaseTemplate(subject, serialNumber, ttlInHour, false)

	// Apply dynamic key usages or fallback to standard Leaf defaults
	if usages != nil && len(usages.KeyUsages) > 0 {
		template.KeyUsage = 0
		for _, ku := range usages.KeyUsages {
			template.KeyUsage |= ku
		}
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	// Apply dynamic extended key usages or fallback to standard Server/Client Auth defaults
	if usages != nil && len(usages.ExtKeyUsages) > 0 {
		template.ExtKeyUsage = usages.ExtKeyUsages
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	template.DNSNames = san.DNSNames
	template.EmailAddresses = san.EmailAddresses
	template.IPAddresses = san.IPAddresses
	template.URIs = san.URIs

	// Key Identifiers
	template.SubjectKeyId, err = generateSKID(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}
	template.AuthorityKeyId = parent.Cert.SubjectKeyId

	leafBytes, err := x509.CreateCertificate(rand.Reader, template, parent.Cert, keyPair.PublicKey, parent.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse leaf certificate: %w", err)
	}

	return leafCert, nil
}
```

---

## `app/domain/constants.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/constants.go`
- **Size:** 670 bytes

```go
package domain

import (
	"crypto/x509"
	"net"
	"net/url"
)

type KeyType string

const (
	RSA_2048   KeyType = "rsa-2048"
	RSA_4096   KeyType = "rsa-4096"
	ECDSA_P224 KeyType = "ecdsa-224"
	ECDSA_P256 KeyType = "ecdsa-256"
	ECDSA_P384 KeyType = "ecdsa-384"
	ECDSA_P521 KeyType = "ecdsa-521"
	ED25519    KeyType = "ed25519"
)

type KeyPair struct {
	PrivateKey any
	PublicKey  any
}

type Certificate struct {
	Cert *x509.Certificate
	Keys *KeyPair
}

type SANs struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

type KeyUsageConfig struct {
	KeyUsages    []x509.KeyUsage
	ExtKeyUsages []x509.ExtKeyUsage
}
```

---

## `app/domain/helpers.go`

- **Full path:** `/home/tassok/CLI/certman/app/domain/helpers.go`
- **Size:** 2033 bytes

```go
package domain

import (
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"fmt"

	"certman/app/utils"
)

// Helper to get KeyPair based on the type
func GetKey(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case RSA_2048:
		privKey, pubKey, err := utils.GetRSAKey(2048)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case RSA_4096:
		privKey, pubKey, err := utils.GetRSAKey(4096)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P224:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P224())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P256:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P256())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P384:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P384())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ECDSA_P521:
		privKey, pubKey, err := utils.GetECDSAKey(elliptic.P521())
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	case ED25519:
		privKey, pubKey, err := utils.GetED25519Key()
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  pubKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// Helper to generate a Subject Key Identifier from a public key
func generateSKID(pubKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SKID using public key: %w", err)
	}
	// Classic RFC 5280 method 1: SHA-1 hash of the value of the BIT STRING subjectPublicKey
	hasher := sha1.New()
	hasher.Write(der)
	return hasher.Sum(nil), nil
}
```

---

## `app/utils/cipher.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/cipher.go`
- **Size:** 1183 bytes

```go
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func Encrypt(plaintext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot generate secure nonce: %w", err)
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot generate gcm AEAD: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("cipher is too short: %v", len(ciphertext))
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, actualCiphertext, nil)
}
```

---

## `app/utils/hash.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/hash.go`
- **Size:** 2004 bytes

```go
package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// const (
// 	argonTime    = 1
// 	argonMemory  = 64 * 1024
// 	argonThreads = 4
// 	argonKeyLen  = 32
// 	argonSaltLen = 16
// )

type Hasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

func NewHasher(time, memory uint32, threads uint8, keyLen, saltLen uint32) *Hasher {
	return &Hasher{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
}

func (a *Hasher) Hash(password []byte) ([]byte, error) {
	salt := make([]byte, a.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.Memory, a.Time, a.Threads, b64Salt, b64Hash)
	return []byte(encoded), nil
}

func (a *Hasher) Verify(password []byte, encodedHash []byte) (bool, error) {
	parts := strings.Split(string(encodedHash), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid argon2id string format")
	}

	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("invalid argon2id parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	hash := argon2.IDKey(password, salt, time, memory, threads, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}
```

---

## `app/utils/key.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/key.go`
- **Size:** 1497 bytes

```go
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

func GetRSAKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate rsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ecdsa key: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

func GetED25519Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ed25519 key: %v", err)
	}
	return privKey, pubKey, nil
}

func ParseKey(privKey, pubKey []byte) (any, any, error) {
	parsedPub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse PKIX public key: %w", err)
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

	return nil, nil, errors.New("unknown key type")
}
```

---

## `app/utils/keyring.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/keyring.go`
- **Size:** 1477 bytes

```go
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "certman"
	accountName = "master-key"
)

// InitMasterKey generates a secure 32-byte key and stores it in Fedora's keyring
func InitMasterKey() error {
	// Check if a key already exists to prevent accidental overwriting
	_, err := keyring.Get(serviceName, accountName)
	if err == nil {
		return errors.New("application is already initialized with a master key")
	}

	// Generate a secure 32-byte (256-bit) AES key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("cannot generate secure bytes: %w", err)
	}
	masterKeyHex := hex.EncodeToString(keyBytes)

	// Save to OS Keyring
	err = keyring.Set(serviceName, accountName, masterKeyHex)
	if err != nil {
		return fmt.Errorf("cannot store key in OS keyring: %w", err)
	}
	return nil
}

// GetMasterKey silently retrieves the key from the OS keyring for cryptography
func GetMasterKey() ([]byte, error) {
	keyHex, err := keyring.Get(serviceName, accountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("app not initialized. Please run the init command first")
		}
		return nil, fmt.Errorf("cannot fetch key from OS keyring: %v", err)
	}

	// Decode back to raw bytes for AES-GCM encryption/decryption
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}
```

---

## `app/utils/read.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/read.go`
- **Size:** 4058 bytes

```go
package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func ReadFile(filePath string) ([]byte, error) {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return nil, err
	}

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file data: %w", err)
	}

	return fileBytes, nil
}

// ReadCert reads file and returns the x509.Certificate formatted cert
// filePath can be linux path, relative path, absolute path or just file name
func ReadCert(filePath string) (*x509.Certificate, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cert: %v", err)
	}

	return cert, nil
}

// ReadKey reads file and returns the pkcs#8 for private key and pkix for public key
// filePath can be linux path, relative path, absolute path or just file name
func ReadKey(filePath string, usedCipher bool) (any, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file does not contains valid key")
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	if usedCipher {
		masterKey, err := GetMasterKey()
		if err != nil {
			return nil, err
		}
		decryptedKey, err := Decrypt(block.Bytes, masterKey)
		if err != nil {
			return nil, err
		}

		key, err := ReturnPrivateKey(decryptedKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	key, err := ReturnKey(block.Bytes, block.Type)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func ReturnKeyWithBlockType(filePath string, usedCipher bool) (any, string, error) {
	fileBytes, err := ReadFile(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("file does not contains valid key")
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, "", fmt.Errorf("file %s does not contain PEM block", filePath)
	}

	if usedCipher {
		masterKey, err := GetMasterKey()
		if err != nil {
			return nil, "", err
		}
		decryptedBytes, err := Decrypt(block.Bytes, masterKey)
		if err != nil {
			return nil, "", err
		}

		blockType := strings.TrimPrefix(block.Type, "ENCRYPTED ")
		key, err := ReturnKey(decryptedBytes, blockType)
		if err != nil {
			return nil, "", err
		}
		return key, blockType, nil
	}

	key, err := ReturnKey(block.Bytes, block.Type)
	if err != nil {
		return nil, "", err
	}

	return key, block.Type, nil
}

func ReturnPrivateKey(keyBytes []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown private key")
}

func ReturnKey(bytes []byte, blockType string) (any, error) {
	switch blockType {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		return pub, nil
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS8PrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return priv, nil
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
		return priv, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
		}
		return pub, nil
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key")
	}
}
```

---

## `app/utils/util.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/util.go`
- **Size:** 5794 bytes

```go
package utils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func ToNetIP(addr string) (net.IP, error) {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return nil, errors.New("unknown or invalid ip address")
	}

	return parsedIP, nil
}

func ToNetIPs(addrs []string) []net.IP {
	var netIPs []net.IP

	for _, ip := range addrs {
		netIP, err := ToNetIP(ip)
		if err != nil {
			log.Printf("skipping invalid IP string: %s\n", ip)
			continue
		}
		netIPs = append(netIPs, netIP)
	}
	return netIPs
}

func ToURL(s string) (*url.URL, error) {
	parsedUrl, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("unknown or invalid url")
	}

	return parsedUrl, nil
}

func ToURLs(urls []string) []*url.URL {
	var urlURLs []*url.URL

	for _, urlStr := range urls {
		u, err := ToURL(urlStr)
		if err != nil {
			log.Printf("skipping invalid URL string: %s\n", urlStr)
			continue
		}
		urlURLs = append(urlURLs, u)
	}
	return urlURLs
}

func ToPem(bytes []byte, blockType string) []byte {
	block := pem.Block{
		Bytes: bytes,
		Type:  blockType,
	}
	pemBytes := pem.EncodeToMemory(&block)

	return pemBytes
}

func GetSerialNumber() (*big.Int, error) {
	sNumLim := new(big.Int).Lsh(big.NewInt(1), 128)
	sNum, err := rand.Int(rand.Reader, sNumLim)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serial number: %w", err)
	}
	return sNum, nil
}

func JoinHomeDir(filePath string) (string, error) {
	if strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		resolvedPath := filepath.Join(home, filePath[2:])
		return resolvedPath, nil
	}
	return filePath, nil
}

func SplitCSV(in string) []string {
	if strings.TrimSpace(in) == "" {
		return nil
	}
	var out []string
	for segment := range strings.SplitSeq(in, ",") {
		if trimmed := strings.TrimSpace(segment); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// FindDir walks rootDir to find targetDirName.
func FindDir(rootDir, targetDirName string) (string, error) {
	var foundPath string

	// Walk the directory tree
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Prevent panicking on permission errors, just skip those directories
			return nil
		}

		if d.IsDir() && d.Name() == targetDirName {
			foundPath = path
			// Return filepath.SkipDir to stop searching once we find the first match
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("cannot walk path: %w", err)
	}

	if foundPath == "" {
		return "", fmt.Errorf("target directory '%s' not found", targetDirName)
	}

	return foundPath, nil
}

// ToSnakeCase converts a string to lowercase and replaces spaces/special characters with underscores.
func ToSnakeCase(str string) string {
	lower := strings.ToLower(strings.TrimSpace(str))

	// 2. Replace one or more consecutive spaces, hyphens, or special chars with a single underscore
	reg := regexp.MustCompile(`[\s\-_]+`)
	snake := reg.ReplaceAllString(lower, "_")

	return snake
}

// GetDeterministicPath returns the path where a certificate *should* reside instantly.
func GetDeterministicPath(subjectCN, issuerCN string, isRootCA bool) (string, error) {
	sub := ToSnakeCase(subjectCN)
	iss := ToSnakeCase(issuerCN)

	if isRootCA && sub == iss {
		return JoinHomeDir(filepath.Join("~/certman/certificates/roots", sub))
	}
	return JoinHomeDir(filepath.Join("~/certman/certificates/issued_by", iss, sub))
}

func ParseKeyUsages(usages []string) []x509.KeyUsage {
	var out []x509.KeyUsage
	m := map[string]x509.KeyUsage{
		"digital-signature":  x509.KeyUsageDigitalSignature,
		"content-commitment": x509.KeyUsageContentCommitment,
		"key-encipherment":   x509.KeyUsageKeyEncipherment,
		"data-encipherment":  x509.KeyUsageDataEncipherment,
		"key-agreement":      x509.KeyUsageKeyAgreement,
		"cert-sign":          x509.KeyUsageCertSign,
		"crl-sign":           x509.KeyUsageCRLSign,
		"encipher-only":      x509.KeyUsageEncipherOnly,
		"decipher-only":      x509.KeyUsageDecipherOnly,
	}
	for _, u := range usages {
		if ku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, ku)
		}
	}
	return out
}

func ParseExtKeyUsages(usages []string) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	m := map[string]x509.ExtKeyUsage{
		"any":              x509.ExtKeyUsageAny,
		"server-auth":      x509.ExtKeyUsageServerAuth,
		"client-auth":      x509.ExtKeyUsageClientAuth,
		"code-signing":     x509.ExtKeyUsageCodeSigning,
		"email-protection": x509.ExtKeyUsageEmailProtection,
		"time-stamping":    x509.ExtKeyUsageTimeStamping,
		"ocsp-signing":     x509.ExtKeyUsageOCSPSigning,
	}
	for _, u := range usages {
		if eku, exists := m[strings.ToLower(strings.TrimSpace(u))]; exists {
			out = append(out, eku)
		}
	}
	return out
}

var durationRegex = regexp.MustCompile(`^(\d+)([hdy])$`)

// ParseTTLToHours parses duration strings like "1000h", "30d", "10y" into total hours.
func ParseTTLToHours(ttlStr string) (int, error) {
	matches := durationRegex.FindStringSubmatch(ttlStr)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid duration format %q: must be a number followed by 'h', 'd', or 'y' (e.g., 1000h, 30d, 10y)", ttlStr)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid number in duration: %v", err)
	}

	unit := matches[2]
	switch unit {
	case "h":
		return value, nil
	case "d":
		return value * 24, nil
	case "y":
		// Approximating a year as 365 days (8760 hours)
		return value * 24 * 365, nil
	default:
		return 0, fmt.Errorf("unsupported time unit: %s", unit)
	}
}
```

---

## `app/utils/write.go`

- **Full path:** `/home/tassok/CLI/certman/app/utils/write.go`
- **Size:** 2964 bytes

```go
package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
func WriteCert(filePath string, certBytes []byte) error {
	// Certificates are public data, standard 0644 permissions are fine
	return write(filePath, "CERTIFICATE", certBytes, 0o644)
}

// WriteKey takes a concrete key (e.g., *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
// and dynamically handles legacy or PKCS#8 formatting.
func WriteKey(filePath string, key any, keyType KeyType, usePKCS8 bool, usePKIX bool, useCipher bool) error {
	if keyType == PUBLIC && usePKIX {
		pubBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return fmt.Errorf("cannot marshal public key: %v", err)
		}
		return write(filePath, "PUBLIC KEY", pubBytes, 0o644)
	}
	if keyType == PUBLIC && !usePKIX {
		pubBytes := x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey))
		return write(filePath, "RSA PUBLIC KEY", pubBytes, 0o644)
	}

	// For PRIVATE keys:
	var blockType string
	var privBytes []byte
	var err error

	if usePKCS8 {
		blockType = "PRIVATE KEY"
		privBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("cannot marshal to PKCS#8: %v", err)
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
				return fmt.Errorf("cannot marshal EC key: %v", err)
			}
		default:
			blockType = "PRIVATE KEY"
			privBytes, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return fmt.Errorf("cannot marshal to PKCS#8: %v", err)
			}
		}
	}
	if useCipher {
		masterKey, err := GetMasterKey()
		if err != nil {
			return fmt.Errorf("failed to retrieve master key for encryption: %w", err)
		}
		encryptedBytes, err := Encrypt(privBytes, masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		privBytes = encryptedBytes
		blockType = "ENCRYPTED " + blockType
	}

	return write(filePath, blockType, privBytes, 0o600)
}

// write is a generic helper to write PEM blocks to disk
func write(filePath string, blockType string, bytes []byte, perm os.FileMode) error {
	path, err := JoinHomeDir(filePath)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("cannot open %s for writing: %v", path, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
	if err != nil {
		return fmt.Errorf("cannot write to the file : %v", err)
	}

	log.Printf("successfully created %s\n", path)
	return nil
}
```

---

## `main.go`

- **Full path:** `/home/tassok/CLI/certman/main.go`
- **Size:** 1131 bytes

```go
package main

import (
	"certman/app/cmd"
	"certman/app/utils"
	"log"
	"os"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Registry *cmd.DataRegistry `kong:"-"`

	Init cmd.InitCmd `cmd:"" help:"Initializes the Application."`

	Read    cmd.ReadCmd    `cmd:"" help:"Reads a Certificate or a specific Key from a file location."`
	Write   cmd.WriteCmd   `cmd:"" help:"Writes Certificate and it's keys into a specified file structure."`
	Verify  cmd.VerifyCmd  `cmd:"" help:"Verifies Certificates and Key pairs."`
	Inspect cmd.InspectCmd `cmd:"" help:"Inspects Certificates and Key pairs. Prints raw information of Certificates or Keys."`
}

func (cli *CLI) AfterApply(ctx *kong.Context) error {
	currentCmd := ctx.Selected().Name

	if currentCmd == "init" {
		return nil
	}

	_, err := utils.GetMasterKey()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	registry := &cmd.DataRegistry{}

	cli := CLI{Registry: registry}

	ctx := kong.Parse(&cli, kong.Name("certman"), kong.Description("A Certificate Management Toolkit"), kong.Bind(registry))

	err := ctx.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
```

---


*Total files processed: 20*
