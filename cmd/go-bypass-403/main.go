package main

import (
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {
	logger := GB403Logger.NewLogger()

	logger.LogInfo("Initializing go-bypass-403...")

	// Initialize payloads first
	if err := payload.InitializePayloadsDir(); err != nil {
		logger.LogError("Failed to initialize payloads: %v", err)
		os.Exit(1)
	}

	runner := cli.NewRunner(logger)

	if err := runner.Initialize(); err != nil {
		logger.LogError("Initialization failed: %v", err)
		os.Exit(1)
	}

	if err := runner.Run(); err != nil {
		logger.LogError("Execution failed: %v", err)
		os.Exit(1)
	}
}
