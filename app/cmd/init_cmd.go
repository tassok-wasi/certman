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
