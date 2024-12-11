package main

import (
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {
	logger.LogInfo("Initializing go-bypass-403...")

	runner := cli.NewRunner()

	if err := runner.Initialize(); err != nil {
		logger.LogError("Initialization failed: %v", err)
		os.Exit(1)
	}

	if err := runner.Run(); err != nil {
		logger.LogError("Execution failed: %v", err)
		os.Exit(1)
	}
}
