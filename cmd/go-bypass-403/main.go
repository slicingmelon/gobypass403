package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {

	// Start pprof server
	startPProf("6060")

	GB403Logger.Info().Msg("Initializing go-bypass-403...")

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

func startPProf(port string) {
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)

	go func() {
		GB403Logger.Info().Msgf("Starting pprof server on localhost:%s", port)
		if err := http.ListenAndServe("localhost:"+port, nil); err != nil {
			GB403Logger.Error().Msgf("Failed to start pprof server: %v", err)
		}
	}()
}
