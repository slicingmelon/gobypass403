package main

import (
	_ "net/http/pprof"
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-bypass-403/internal/utils/profiler"
)

func main() {
	GB403Logger.Info().Msgf("Initializing go-bypass-403...")

	if err := payload.InitializePayloadsDir(); err != nil {
		GB403Logger.Error().Msgf("Failed to initialize payloads: %v", err)
		os.Exit(1)
	}

	// Initialize CLI runner which processes all flags (including the -profile flag)
	runner := cli.NewRunner()
	if err := runner.Initialize(); err != nil {
		GB403Logger.Error().Msgf("Initialization failed: %v", err)
		os.Exit(1)
	}

	// If profile option is enabled, start the profiler
	if runner.RunnerOptions.Profile {
		p := profiler.NewProfiler()
		if err := p.Start(); err != nil {
			GB403Logger.Error().Msgf("Failed to start profiler: %v", err)
		} else {
			defer p.Stop()
		}
	}

	if err := runner.Run(); err != nil {
		GB403Logger.Error().Msgf("Execution failed: %v", err)
		os.Exit(1)
	}
}
