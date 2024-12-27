package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

func main() {
	// Start pprof server first
	startPProf("6060")

	// Start with a GC to clean up
	runtime.GC()

	// Create unique heap profile file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	f, err := os.Create(fmt.Sprintf("heap-%s.prof", timestamp))
	if err != nil {
		GB403Logger.Error().Msgf("Could not create heap profile: %v", err)
	}
	defer f.Close()

	// Write single heap profile at end
	defer func() {
		GB403Logger.Info().Msg("Writing heap profile...")
		runtime.GC() // Force GC before writing
		if err := pprof.WriteHeapProfile(f); err != nil {
			GB403Logger.Error().Msgf("Could not write heap profile: %v", err)
		}
	}()

	GB403Logger.Info().Msg("Initializing go-bypass-403...")

	// Rest of your code...
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
