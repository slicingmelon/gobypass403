package main

import (
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {
	logger.Info("Initializing go-bypass-403...")

	runner := cli.NewRunner()

	if err := runner.Initialize(); err != nil {
		logger.Error("Initialization failed: %v", err)
		os.Exit(1)
	}

	if err := runner.Run(); err != nil {
		logger.Error("Execution failed: %v", err)
		os.Exit(1)
	}
}
