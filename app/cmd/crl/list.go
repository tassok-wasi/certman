package crl

import (
	"certman/db/base"
	"context"
	"fmt"
	"os"
	"text/tabwriter"
)

type ListCmd struct {
	Limit         int    `name:"limit" short:"l" help:"Limit limits the output. if not given then it will show everything."`
	Offset        int    `name:"offset" short:"o" help:"Skip first N rows."`
	ISerialNumber string `name:"isn" required:"" help:"Serial Number of the Issuer Certificate."`
}

func (lc *ListCmd) Run(ctx context.Context, query base.Querier) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	fmt.Fprintln(w, "ID\tNAME\tCRL NUMBER\tTHIS UPDATE\tNEXT UPDATE")
	fmt.Fprintln(w, "--\t----\t----------\t-----------\t-----------")

	if lc.Limit == 0 && lc.Offset == 0 {
		crls, err := query.ListAllCRLs(ctx, lc.ISerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get crls from db: %w", err)
		}

		if len(crls) == 0 {
			fmt.Printf("No CRLs found for issuer serial: %s\n", lc.ISerialNumber)
			return nil
		}

		for _, crl := range crls {
			thisUpdateStr := crl.ThisUpdate.Format("2006-01-02 15:04:05")
			nextUpdateStr := crl.NextUpdate.Format("2006-01-02 15:04:05")

			fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\n",
				crl.ID,
				crl.Name,
				crl.CrlNumber,
				thisUpdateStr,
				nextUpdateStr,
			)
		}
		return w.Flush()
	} else {
		crls, err := query.ListCRLs(ctx, base.ListCRLsParams{
			IssuerSerialNumber: lc.ISerialNumber,
			Limit:              int64(lc.Limit),
			Offset:             int64(lc.Offset),
		})
		if err != nil {
			return fmt.Errorf("failed to get crls from db: %w", err)
		}

		if len(crls) == 0 {
			fmt.Printf("No CRLs found for issuer serial: %s\n", lc.ISerialNumber)
			return nil
		}

		for _, crl := range crls {
			thisUpdateStr := crl.ThisUpdate.Format("2006-01-02 15:04:05")
			nextUpdateStr := crl.NextUpdate.Format("2006-01-02 15:04:05")

			fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\n",
				crl.ID,
				crl.Name,
				crl.CrlNumber,
				thisUpdateStr,
				nextUpdateStr,
			)
		}
		return w.Flush()
	}
}
