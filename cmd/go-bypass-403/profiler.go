package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/goccy/go-graphviz"
	"github.com/google/pprof/profile"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	// Create profile directory
	if err := os.MkdirAll(p.profileDir, 0755); err != nil {
		GB403Logger.Error().Msgf("Failed to create profile directory: %v", err)
		return fmt.Errorf("create profile directory: %w", err)
	}

	// Start CPU profiling
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

	// Set memory profile rate
	runtime.MemProfileRate = 1

	// Force garbage collection before profiling
	runtime.GC()

	return nil
}

func (p *Profiler) Stop() {
	// Force garbage collection before stopping
	runtime.GC()

	// Stop CPU profiling
	pprof.StopCPUProfile()
	if p.cpuFile != nil {
		p.cpuFile.Close()
	}

	// Write other profiles and generate visualizations
	for _, profType := range []string{"heap", "allocs", "goroutine", "cpu"} {
		// Write the profile file
		if err := p.writeProfile(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to write %s profile: %v", profType, err)
			continue
		}

		// Generate dot file
		if err := p.generateDotFile(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to generate %s dot file: %v", profType, err)
			continue
		}

		// Generate SVG
		if err := p.generateSVG(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to generate %s SVG: %v", profType, err)
			continue
		}
	}

	GB403Logger.Info().Msgf("Profile data and visualizations written to: %s", p.profileDir)
}

func (p *Profiler) writeProfile(profType string) error {
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
		return pprof.Lookup(profType).WriteTo(f, 0)
	case "cpu":
		// CPU profile is already written by pprof.StopCPUProfile()
		return nil
	}
	return nil
}

func (p *Profiler) generateDotFile(profType string) error {
	dotPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.dot", profType, p.timestamp))

	// Create dot file
	dotFile, err := os.Create(dotPath)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to create dot file: %v", err)
		return fmt.Errorf("create dot file: %w", err)
	}
	defer dotFile.Close()

	switch profType {
	case "heap", "allocs", "goroutine":
		prof := pprof.Lookup(profType)
		if prof == nil {
			return fmt.Errorf("no %s profile found", profType)
		}
		// Write in debug=1 format for human-readable output
		if err := prof.WriteTo(dotFile, 1); err != nil {
			GB403Logger.Error().Msgf("Failed to write dot file: %v", err)
			return fmt.Errorf("write dot file: %w", err)
		}

	case "cpu":
		// For CPU profiles, we need to read from the file
		profPath := filepath.Join(p.profileDir, fmt.Sprintf("cpu-%s.prof", p.timestamp))
		f, err := os.Open(profPath)
		if err != nil {
			GB403Logger.Error().Msgf("Failed to open CPU profile: %v", err)
			return fmt.Errorf("open CPU profile: %w", err)
		}
		defer f.Close()

		prof, err := profile.Parse(f)
		if err != nil {
			GB403Logger.Error().Msgf("Failed to parse CPU profile: %v", err)
			return fmt.Errorf("parse CPU profile: %w", err)
		}

		// For CPU profiles from profile.Parse, we use Write
		if err := prof.Write(dotFile); err != nil {
			GB403Logger.Error().Msgf("Failed to write CPU profile: %v", err)
			return fmt.Errorf("write CPU profile: %w", err)
		}

	default:
		return fmt.Errorf("unknown profile type: %s", profType)
	}

	return nil
}

func (p *Profiler) generateSVG(profType string) error {
	profPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))
	dotPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.dot", profType, p.timestamp))
	svgPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.svg", profType, p.timestamp))

	// Skip if profile file is empty
	if fi, err := os.Stat(profPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("empty or missing profile file: %s", profPath)
	}

	// Initialize graphviz
	ctx := context.Background()
	g, err := graphviz.New(ctx)
	if err != nil {
		return fmt.Errorf("create graphviz: %w", err)
	}
	defer g.Close()

	// Read the dot file
	dotContent, err := os.ReadFile(dotPath)
	if err != nil {
		return fmt.Errorf("read dot file: %w", err)
	}

	// Clean and validate dot content
	dotContent = bytes.TrimSpace(dotContent)
	if len(dotContent) == 0 {
		return fmt.Errorf("empty dot file")
	}

	// Parse the dot content with error handling
	graph, err := graphviz.ParseBytes(dotContent)
	if err != nil {
		// Try to sanitize the content if parsing fails
		sanitized := strings.ReplaceAll(string(dotContent), "\x00", "")
		graph, err = graphviz.ParseBytes([]byte(sanitized))
		if err != nil {
			return fmt.Errorf("parse dot content: %w", err)
		}
	}
	defer graph.Close()

	// Render to SVG with context and timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := g.RenderFilename(ctx, graph, graphviz.SVG, svgPath); err != nil {
		return fmt.Errorf("render SVG: %w", err)
	}

	return nil
}
