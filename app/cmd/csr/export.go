package csr

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ExportCmd struct {
	ID     int64  `arg:"" help:"ID of the CSR to Export."`
	Path   string `name:"path" short:"p" type:"path" help:"Path to export the file. [file name must be omitted]"`
	Format string `name:"format" short:"f" default:"pem" help:"Specific format to export (e.g., pem, der)"`
}

func (ec *ExportCmd) Run(ctx context.Context, query base.Querier) error {
	dbCsr, err := query.GetCSRByID(ctx, ec.ID)
	if err != nil {
		return fmt.Errorf("failed to get CSR from db: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(ec.Format))
	if format == "" {
		format = "pem"
	}

	var data []byte
	var ext string

	switch format {
	case "pem":
		ext = ".pem"
		data = []byte(dbCsr.CsrPem)

	case "der":
		ext = ".der"
		block, _ := pem.Decode([]byte(dbCsr.CsrPem))
		if block == nil {
			return errors.New("failed to decode PEM block into DER")
		}
		data = block.Bytes

	default:
		return fmt.Errorf("unsupported format '%s': expected 'pem' or 'der'", ec.Format)
	}

	var outputDir string
	if ec.Path != "" {
		outputDir, err = utils.JoinHomeDir(ec.Path)
		if err != nil {
			return fmt.Errorf("failed to resolve output path: %w", err)
		}
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory: %w", err)
		}
	}

	filename := utils.SanitizeFilename(dbCsr.CommonName, "exported_csr") + ext
	csrFilePath := filepath.Join(outputDir, filename)

	if err := os.WriteFile(csrFilePath, data, 0o644); err != nil {
		return fmt.Errorf("could not write to file %s: %w", csrFilePath, err)
	}

	fmt.Printf("Successfully exported CSR to: %s\n", csrFilePath)
	return nil
}
