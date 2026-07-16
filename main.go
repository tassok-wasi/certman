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
