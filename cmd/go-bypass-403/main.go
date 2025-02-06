package main

import (
	_ "net/http/pprof"
	"os"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

const (
	enablePProf = false // Set to true to enable profiling
)

func main() {
	var profiler *Profiler
	if enablePProf {
		profiler = NewProfiler()
		if err := profiler.Start(); err != nil {
			GB403Logger.Error().Msgf("Failed to start profiler: %v", err)
		} else {
			defer profiler.Stop()
		}
	}

	GB403Logger.Info().Msgf("Initializing go-bypass-403...")

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
