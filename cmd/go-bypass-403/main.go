package main

import (
	"fmt"
	"net/http"
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

var (
	enablePProf = true
	pprofPort   = "6060"
	pprofDir    = "_pprof"
)

func main() {
	if enablePProf {
		// Start pprof server first
		startPProf(pprofPort)

		defer func() {
			timestamp := time.Now().Format("20060102-150405")

			// Ensure cleanup happens in reverse order
			if err := writeProfiles(timestamp); err != nil {
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

func writeProfiles(timestamp string) error {
	// Create profile directory
	profileDir := filepath.Join(pprofDir, fmt.Sprintf("profile_%s", timestamp))
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("could not create profile directory: %v", err)
	}

	// Write heap profile
	if err := writeProfile(profileDir, "heap", timestamp, func(f *os.File) error {
		return pprof.WriteHeapProfile(f)
	}); err != nil {
		return fmt.Errorf("heap profile error: %v", err)
	}

	// Write goroutine profile
	if err := writeProfile(profileDir, "goroutine", timestamp, func(f *os.File) error {
		return pprof.Lookup("goroutine").WriteTo(f, 0)
	}); err != nil {
		return fmt.Errorf("goroutine profile error: %v", err)
	}

	// Write CPU profile (if needed)
	if err := writeProfile(profileDir, "cpu", timestamp, func(f *os.File) error {
		return pprof.StartCPUProfile(f)
	}); err != nil {
		return fmt.Errorf("CPU profile error: %v", err)
	}
	defer pprof.StopCPUProfile()

	GB403Logger.Info().Msgf("Profiles written to: %s", profileDir)
	return nil
}

func writeProfile(dir, name, timestamp string, writeFn func(*os.File) error) error {
	filename := filepath.Join(dir, fmt.Sprintf("%s-%s.prof", name, timestamp))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create %s profile: %v", name, err)
	}
	defer f.Close()

	if err := writeFn(f); err != nil {
		return fmt.Errorf("could not write %s profile: %v", name, err)
	}

	return nil
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
