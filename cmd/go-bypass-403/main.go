package main

import (
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {

	GB403Logger.Info().Msgf("Initializing go-bypass-403...")

	// Initialize payloads first
	if err := payload.InitializePayloadsDir(); err != nil {
		GB403Logger.Error().Msgf("Failed to initialize payloads: %v", err)
		os.Exit(1)
	}

	runner := cli.NewRunner()

	if err := runner.Initialize(); err != nil {
		GB403Logger.Error().Msgf("Initialization failed: %v", err)
		os.Exit(1)
	}

	if err := runner.Run(); err != nil {
		GB403Logger.Error().Msgf("Execution failed: %v", err)
		os.Exit(1)
	}
}
