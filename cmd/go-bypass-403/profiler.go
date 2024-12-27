package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

const (
	_pProfDir = "_pprof"
)

func WriteProfiles(timestamp string) error {
	profileDir := filepath.Join(_pProfDir, fmt.Sprintf("profile_%s", timestamp))

	// Write and generate visualizations for each profile type
	profileTypes := []string{"heap", "allocs", "goroutine"}
	for _, profType := range profileTypes {
		// Write profile
		if err := writeProfile(profileDir, profType, timestamp, func(f *os.File) error {
			switch profType {
			case "heap":
				return pprof.WriteHeapProfile(f)
			case "allocs":
				return pprof.Lookup("allocs").WriteTo(f, 0)
			case "goroutine":
				return pprof.Lookup("goroutine").WriteTo(f, 0)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("%s profile error: %v", profType, err)
		}

		// Generate visualizations
		if err := GenerateVisualizations(profileDir, profType, timestamp); err != nil {
			GB403Logger.Error().Msgf("Could not generate %s visualizations: %v", profType, err)
		}
	}

	GB403Logger.Info().Msgf("Profiles and visualizations written to: %s", profileDir)
	return nil
}

func GenerateVisualizations(dir, profType, timestamp string) error {
	profPath := filepath.Join(dir, fmt.Sprintf("%s-%s.prof", profType, timestamp))

	// Generate DOT file
	dotPath := filepath.Join(dir, fmt.Sprintf("%s-%s.dot", profType, timestamp))
	dotCmd := exec.Command("go", "tool", "pprof", "-dot", profPath)
	dotFile, err := os.Create(dotPath)
	if err != nil {
		return fmt.Errorf("could not create %s DOT file: %v", profType, err)
	}
	dotCmd.Stdout = dotFile
	if err := dotCmd.Run(); err != nil {
		dotFile.Close()
		return fmt.Errorf("could not generate %s DOT file: %v", profType, err)
	}
	dotFile.Close()

	// Generate SVG file
	svgPath := filepath.Join(dir, fmt.Sprintf("%s-%s.svg", profType, timestamp))
	svgCmd := exec.Command("go", "tool", "pprof", "-svg", profPath)
	svgFile, err := os.Create(svgPath)
	if err != nil {
		return fmt.Errorf("could not create %s SVG file: %v", profType, err)
	}
	svgCmd.Stdout = svgFile
	if err := svgCmd.Run(); err != nil {
		svgFile.Close()
		return fmt.Errorf("could not generate %s SVG file: %v", profType, err)
	}
	svgFile.Close()

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

func StartPProf(port string) {
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)

	go func() {
		GB403Logger.Info().Msgf("Starting pprof server on localhost:%s", port)
		if err := http.ListenAndServe("localhost:"+port, nil); err != nil {
			GB403Logger.Error().Msgf("Failed to start pprof server: %v", err)
		}
	}()
}
