/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package profiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/core/utils/logger"
)

type Profiler struct {
	timestamp  string
	profileDir string
	cpuFile    *os.File
}

func NewProfiler() *Profiler {
	timestamp := time.Now().Format("20060102-150405")
	return &Profiler{
		timestamp:  timestamp,
		profileDir: filepath.Join("_pprof", fmt.Sprintf("profile_%s", timestamp)),
	}
}

func (p *Profiler) Start() error {
	if err := os.MkdirAll(p.profileDir, 0755); err != nil {
		GB403Logger.Error().Msgf("Failed to create profile directory: %v", err)
		return fmt.Errorf("create profile directory: %w", err)
	}

	cpuFile, err := os.Create(filepath.Join(p.profileDir, fmt.Sprintf("cpu-%s.prof", p.timestamp)))
	if err != nil {
		GB403Logger.Error().Msgf("Failed to create CPU profile: %v", err)
		return fmt.Errorf("create CPU profile: %w", err)
	}
	p.cpuFile = cpuFile

	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		cpuFile.Close()
		GB403Logger.Error().Msgf("Failed to start CPU profile: %v", err)
		return fmt.Errorf("start CPU profile: %w", err)
	}

	runtime.MemProfileRate = 1
	runtime.GC()
	return nil
}

func (p *Profiler) Stop() {
	runtime.GC()
	pprof.StopCPUProfile()
	if p.cpuFile != nil {
		p.cpuFile.Close()
	}

	// Check CPU profile size
	cpuPath := filepath.Join(p.profileDir, fmt.Sprintf("cpu-%s.prof", p.timestamp))
	if fi, err := os.Stat(cpuPath); err == nil && fi.Size() == 0 {
		GB403Logger.Error().Msgf("CPU profile is empty - program may have run too quickly to capture meaningful data")
		// Remove empty CPU profile
		os.Remove(cpuPath)
	}

	for _, profType := range []string{"heap", "allocs", "goroutine"} {
		if err := p.WriteProfile(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to write %s profile: %v", profType, err)
			continue
		}

		if err := p.GenerateVisualization(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to generate %s visualization: %v", profType, err)
			GB403Logger.Error().Msgf("Please make sure that you have graphviz installed and available in your PATH\n")
			continue
		}

	}

	// Handle CPU profile separately
	if fi, err := os.Stat(cpuPath); err == nil && fi.Size() > 0 {
		if err := p.GenerateVisualization("cpu"); err != nil {
			GB403Logger.Error().Msgf("Failed to generate CPU visualization: %v", err)
		}
	}

	GB403Logger.Info().Msgf("Profile data and visualizations written to: %s", p.profileDir)
}

func (p *Profiler) WriteProfile(profType string) error {
	filename := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create profile: %w", err)
	}
	defer f.Close()

	switch profType {
	case "heap":
		return pprof.WriteHeapProfile(f)
	case "allocs", "goroutine":
		prof := pprof.Lookup(profType)
		if prof == nil {
			return fmt.Errorf("no %s profile found", profType)
		}
		return prof.WriteTo(f, 0)
	case "cpu":
		return nil // CPU profile is already written
	}
	return nil
}

func (p *Profiler) GenerateVisualization(profType string) error {
	profPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))
	dotPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.dot", profType, p.timestamp))
	svgPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.svg", profType, p.timestamp))

	// Skip if profile file is empty
	if fi, err := os.Stat(profPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("empty or missing profile file: %s", profPath)
	}

	// Generate DOT file
	dotCmd := exec.Command("go", "tool", "pprof", "-dot", profPath)
	dotOutput, err := dotCmd.Output()
	if err != nil {
		return fmt.Errorf("generate dot: %w", err)
	}

	if err := os.WriteFile(dotPath, dotOutput, 0644); err != nil {
		return fmt.Errorf("write dot file: %w", err)
	}

	// Generate SVG file
	svgCmd := exec.Command("go", "tool", "pprof", "-svg", profPath)
	svgOutput, err := svgCmd.Output()
	if err != nil {
		return fmt.Errorf("generate svg: %w", err)
	}

	if err := os.WriteFile(svgPath, svgOutput, 0644); err != nil {
		return fmt.Errorf("write svg file: %w", err)
	}

	return nil
}
