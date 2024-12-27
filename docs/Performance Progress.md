# Performance Progress

This document will track the performance progress of the project, based on the pprof data.

# 2024-12-27

Performance Characteristics (from profiles)

1. Memory Usage Hotspots:
- TLS Handshake: ~81MB
- Request Processing: ~120MB
- HMAC Operations: ~22MB

2. CPU Profile Highlights:
   - Memory Allocation: 52.13%
   - Request Processing: 64.69%
   - TLS Operations: 32.50%

3. Goroutine Distribution:
   - Request Processing: 70%
   - Connection Management: 16.67%
   - Profiling: 3.33%


```graphviz
digraph G {
    rankdir=LR;
    node [shape=box, style=filled, fillcolor=lightgray];
    
    // Main components
    main [label="Main Entry\n(CPU: 3.33%)"];
    runner [label="Runner\n(Memory: 15%)"];
    scanner [label="Scanner Engine\n(CPU: 64.69%)"];
    payload [label="Payload Generator\n(Memory: 22MB)"];
    http [label="HTTP Client\n(Memory: 120MB)"];
    
    // Profiling components
    pprof [label="pprof Server", fillcolor=lightblue];
    profiler [label="Profile Collector", fillcolor=lightblue];
    
    // Relationships
    main -> runner;
    main -> pprof;
    runner -> scanner;
    scanner -> payload;
    scanner -> http;
    pprof -> profiler;
    
    // Subgraph for core processing
    subgraph cluster_0 {
        label = "Core Processing";
        style = filled;
        color = lightgrey;
        scanner;
        payload;
        http;
    }
}

```

