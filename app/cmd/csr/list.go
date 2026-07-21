package csr

import (
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListCmd struct {
	Limit  int    `name:"limit" short:"l" help:"Limit limits the output. if not given then it will show everything."`
	Offset int    `name:"offset" short:"o" help:"Skip first N rows."`
	Status string `name:"status" short:"s" help:"Status defines Which are the data to show e.g., PENDING, REJECTED, SIGNED."`
}

// unifiedCSR normalizes the fields from different query row models
type unifiedCSR struct {
	ID                      int64
	CommonName              string
	KeyName                 string
	Status                  string
	CertificateSerialNumber sql.NullString
}

func (lc *ListCmd) Run(ctx context.Context, query base.Querier) error {
	statusFilter := sql.NullString{
		String: lc.Status,
		Valid:  lc.Status != "",
	}

	var unifiedList []unifiedCSR

	if lc.Limit == 0 && lc.Offset == 0 {
		csrs, err := query.ListAllCSRs(ctx, statusFilter)
		if err != nil {
			return fmt.Errorf("failed to get CSRs from db: %w", err)
		}
		for _, c := range csrs {
			unifiedList = append(unifiedList, unifiedCSR{
				ID:                      c.ID,
				CommonName:              c.CommonName,
				KeyName:                 c.KeyName,
				Status:                  c.Status,
				CertificateSerialNumber: c.CertificateSerialNumber,
			})
		}
	} else {
		csrs, err := query.ListCSRs(ctx, base.ListCSRsParams{
			Status: statusFilter,
			Limit:  int64(lc.Limit),
			Offset: int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to get CSRs from db: %w", err)
		}
		for _, c := range csrs {
			unifiedList = append(unifiedList, unifiedCSR{
				ID:                      c.ID,
				CommonName:              c.CommonName,
				KeyName:                 c.KeyName,
				Status:                  c.Status,
				CertificateSerialNumber: c.CertificateSerialNumber,
			})
		}
	}

	if len(unifiedList) == 0 {
		fmt.Println("No CSRs found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	if lc.Status == "SIGNED" {
		fmt.Fprintln(w, "ID\tCOMMON NAME\tKEY NAME\tSTATUS\tCERTIFICATE SERIAL NUMBER")
		fmt.Fprintln(w, "--\t-----------\t--------\t------\t-------------------------")
	} else {
		fmt.Fprintln(w, "ID\tCOMMON NAME\tKEY NAME\tSTATUS")
		fmt.Fprintln(w, "--\t-----------\t--------\t------")
	}

	for _, csr := range unifiedList {
		if lc.Status == "SIGNED" {
			serial := "-"
			if csr.CertificateSerialNumber.Valid {
				serial = csr.CertificateSerialNumber.String
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
				csr.ID,
				csr.CommonName,
				csr.KeyName,
				csr.Status,
				serial,
			)
		} else {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
				csr.ID,
				csr.CommonName,
				csr.KeyName,
				csr.Status,
			)
		}
	}

	return w.Flush()
}
