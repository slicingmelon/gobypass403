package main

import (
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
	if err := os.MkdirAll(p.profileDir, 0755); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	// Start CPU profiling
	cpuFile, err := os.Create(filepath.Join(p.profileDir, fmt.Sprintf("cpu-%s.prof", p.timestamp)))
	if err != nil {
		return fmt.Errorf("create CPU profile: %w", err)
	}
	p.cpuFile = cpuFile

	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		cpuFile.Close()
		return fmt.Errorf("start CPU profile: %w", err)
	}

	// Enable memory profiling
	runtime.MemProfileRate = 1
	return nil
}

func (p *Profiler) Stop() {
	pprof.StopCPUProfile()
	if p.cpuFile != nil {
		p.cpuFile.Close()
	}

	// Write other profiles
	for _, profType := range []string{"heap", "allocs", "goroutine"} {
		if err := p.writeProfile(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to write %s profile: %v", profType, err)
			continue
		}
		if err := p.generateSVG(profType); err != nil {
			GB403Logger.Error().Msgf("Failed to generate %s visualization: %v", profType, err)
		}
	}
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
	}
	return nil
}

func (p *Profiler) generateSVG(profType string) error {
	profPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.prof", profType, p.timestamp))

	prof, err := p.parseProfile(profPath)
	if err != nil {
		return err
	}

	g, err := graphviz.New()
	if err != nil {
		return fmt.Errorf("create graphviz: %w", err)
	}
	defer g.Close()

	graph, err := g.Graph()
	if err != nil {
		return fmt.Errorf("create graph: %w", err)
	}
	defer graph.Close()

	if err := p.renderGraph(prof, graph); err != nil {
		return err
	}

	svgPath := filepath.Join(p.profileDir, fmt.Sprintf("%s-%s.svg", profType, p.timestamp))
	return g.RenderFilename(graph, graphviz.SVG, svgPath)
}

func (p *Profiler) parseProfile(path string) (*profile.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()
	return profile.Parse(f)
}

func (p *Profiler) renderGraph(prof *profile.Profile, graph *graphviz.Graph) error {
	nodes := make(map[uint64]*graphviz.Node)

	for _, sample := range prof.Sample {
		var prevNode *graphviz.Node
		for i, loc := range sample.Location {
			if len(loc.Line) == 0 {
				continue
			}

			fn := loc.Line[0].Function
			node, exists := nodes[fn.ID]
			if !exists {
				var err error
				node, err = graph.CreateNode(fn.Name)
				if err != nil {
					return fmt.Errorf("create node: %w", err)
				}
				nodes[fn.ID] = node
			}

			if prevNode != nil {
				if _, err := graph.CreateEdge("", prevNode, node); err != nil {
					return fmt.Errorf("create edge: %w", err)
				}
			}

			if i == 0 {
				node.SetColor("red")
			}
			prevNode = node
		}
	}
	return nil
}
