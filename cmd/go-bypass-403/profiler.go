package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
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

	runtime.MemProfileRate = 1
	return nil
}

func (p *Profiler) Stop() {
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
		}

		// Generate SVG
		if err := p.generateSVG(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to generate %s SVG: %v", profType, err)
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
	profPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))
	dotPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.dot", profType, p.timestamp))

	// Open and parse the profile
	f, err := os.Open(profPath)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to open profile: %v", err)
		return fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()

	prof, err := profile.Parse(f)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse profile: %v", err)
		return fmt.Errorf("parse profile: %w", err)
	}

	// Create dot file
	dotFile, err := os.Create(dotPath)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to create dot file: %v", err)
		return fmt.Errorf("create dot file: %w", err)
	}
	defer dotFile.Close()

	// Write the profile in dot format
	if err := prof.Write(dotFile); err != nil {
		return fmt.Errorf("write dot file: %w", err)
	}

	return nil
}

func (p *Profiler) generateSVG(profType string) error {
	profPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))
	svgPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.svg", profType, p.timestamp))

	// Open and parse the profile
	f, err := os.Open(profPath)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to open profile: %v", err)
		return fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()

	prof, err := profile.Parse(f)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse profile: %v", err)
		return fmt.Errorf("parse profile: %w", err)
	}

	// Initialize graphviz with context
	ctx := context.Background()
	g, err := graphviz.New(ctx)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to create graphviz: %v", err)
		return fmt.Errorf("create graphviz: %w", err)
	}
	defer g.Close()

	// Create graph
	graph, err := g.Graph()
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer graph.Close()

	// Create temporary dot file
	dotPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.dot", profType, p.timestamp))
	dotFile, err := os.Create(dotPath)
	if err != nil {
		return fmt.Errorf("create dot file: %w", err)
	}
	defer dotFile.Close()

	// Write profile data to dot format
	if err := prof.Write(dotFile); err != nil {
		return fmt.Errorf("write dot file: %w", err)
	}

	// Read the dot file back
	dotContent, err := os.ReadFile(dotPath)
	if err != nil {
		return fmt.Errorf("read dot file: %w", err)
	}

	// Parse the dot content
	graph, err = graphviz.ParseBytes(dotContent)
	if err != nil {
		return fmt.Errorf("parse dot content: %w", err)
	}

	// Render to SVG
	return g.RenderFilename(ctx, graph, graphviz.SVG, svgPath)
}
