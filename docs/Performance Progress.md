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


## 1. Memory Profile (heap and allocs) Analysis
Key Observations:

- High Memory Usage in rawhttp Module:
    - Significant memory allocation (~120MB) occurs in rawhttp.(*RequestPool).ProcessRequests.func1 and its worker functions (rawhttp.(*requestWorker).ProcessRequestJob)​.
    - This suggests a potential inefficiency in the way payloads or requests are being managed.

- JSON Handling (scanner.AppendResultsToJSON):
    - Noticeable memory allocation during results serialization and writing to JSON files​.
    - Functions like encoding/json.(*Encoder).Encode are consuming significant memory.

-Buffer Growth:
    - Excessive memory allocation in bytes.growSlice indicates that buffer resizing may not be optimized for larger payloads​.

Recommendations:

- Optimize Worker Memory Usage:
  - Reuse Buffers: Use sync.Pool to manage and reuse byte buffers for requests and responses to avoid repeated allocations.
  - Payload Segmentation: Consider breaking down payloads into smaller, manageable chunks to reduce memory pressure.

- Optimize JSON Serialization:
  - Serialize results incrementally to avoid loading all results into memory at once.
  - If feasible, use a more memory-efficient library or custom serialization.

- Buffer Preallocation:
  - For known or estimated payload sizes, preallocate buffers to minimize resizing overhead.

## 2. CPU Profile (cpu) Analysis

Key Observations:

- Heavy CPU Usage in fasthttp Transport Layer:
    - fasthttp.(*transport).RoundTrip and related functions dominate the CPU profile​

  - TLS Handshake and Buffer Flushing:
    - TLS handshake functions (crypto/tls.*) and buffer flushing (bufio.(*Writer).Flush) are significant contributors​

- JSON Encoding Overhead:
    - JSON serialization (encoding/json) contributes to CPU usage during result handling​
​

Recommendations:

- Connection Reuse:
    - Ensure connections are reused wherever possible, especially for the same host, to reduce the overhead of repeated TLS handshakes.

- Optimize Buffer Flushing:
  - Reduce the frequency of flushing in bufio.Writer by increasing the buffer size.

- Parallelize Non-blocking Tasks:
    - Offload JSON serialization to a separate goroutine or worker to reduce blocking impact on request handling.

- Parallelize Non-blocking Tasks:
    - Offload JSON serialization to a separate goroutine or worker to reduce blocking impact on request handling.
  
# 3. Goroutine Profile Analysis

Key Observations:

- Excessive Idle Goroutines:
  - Many goroutines are in a parked state (runtime.gopark), indicating potential inefficiency in worker utilization​.

- Limited Active Goroutines:
  - Goroutines related to fasthttp tasks (fasthttp.(*TCPDialer)) dominate active states but may not be optimally utilized​.

Recommendations:

- Improve Worker Utilization:
    - Dynamically adjust the worker pool size based on payload size and response times to minimize idle workers.
    - Implement backpressure mechanisms to avoid overwhelming the pool with pending tasks.

- Monitor Goroutine Lifetimes:
    - Ensure goroutines exit cleanly after task completion to avoid leaks.