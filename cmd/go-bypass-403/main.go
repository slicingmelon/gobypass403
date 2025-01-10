package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

const (
	enablePProf = false
	pProfPort   = "6060"
	pProfDir    = "_pprof"
)

func main() {
	if enablePProf {
		// Start pprof server first
		StartPProf(pProfPort)

		timestamp := time.Now().Format("20060102-150405")

		// Create profile directory
		profileDir := filepath.Join(pProfDir, fmt.Sprintf("profile_%s", timestamp))
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			GB403Logger.Error().Msgf("Could not create profile directory: %v", err)
			os.Exit(1)
		}

		// Start CPU right away
		cpuFile, err := os.Create(filepath.Join(profileDir, fmt.Sprintf("cpu-%s.prof", timestamp)))
		if err != nil {
			GB403Logger.Error().Msgf("Could not create CPU profile: %v", err)
		} else {
			if err := pprof.StartCPUProfile(cpuFile); err != nil {
				GB403Logger.Error().Msgf("Could not start CPU profile: %v", err)
			}
			defer func() {
				pprof.StopCPUProfile()
				cpuFile.Close()

				// Export .dot and .svg files for each profile
				if err := GenerateVisualizations(profileDir, "cpu", timestamp); err != nil {
					GB403Logger.Error().Msgf("Could not generate CPU visualizations: %v", err)
				}
			}()
		}

		// Enable memory allocation profiling (Profile all allocations)
		runtime.MemProfileRate = 1

		// Defer other profiles
		defer func() {
			if err := WriteProfiles(timestamp); err != nil {
				GB403Logger.Error().Msgf("Failed to write profiles: %v", err)
			}
		}()

		// Start with a GC to clean up
		runtime.GC()
	}

	GB403Logger.Info().Msg("Initializing go-bypass-403...")

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
