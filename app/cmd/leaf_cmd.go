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
