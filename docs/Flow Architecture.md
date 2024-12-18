# Go Bypass 403 - Flow Architecture

## Command Line Interface (CLI Layer)

User input processing and execution control.

- Advanced Parsing: Support for both short and long flag formats.
- Configuration Management: Validates and loads configurations with intelligent defaults.
- URL Preprocessing: Ensures input structure correctness and optimizes for downstream tasks.
- Lifecycle Management: Orchestrates task execution and resource cleanup.
- Error Handling: Structured approach to preserve context for debugging.
- Autoupdater - main tool and payloads.

# 2. Recon Module

Performs a fast reconnaissance on the target URL(s) before the main engine is started. 

- Deep Fingerprinting: Identifies service types and target behaviors.
- DNS Resolution: Fast DNS resolution with fallback and caching mechanisms.
- Port Discovery: Multi-threaded and efficient identification of open services.
- High-Performance Cache: Implements an LRU strategy to minimize redundant operations.
- Filters non-responsive/nonresolvable targets.
- Caches IPs, open ports, IPv4/IPv6, and other data.


# 3. Scanner Engine

Coordinates and executes scanning workflows.

- Bypass Modules Orchestration: Modular approach for various bypass techniques.
- Worker Pool Management: Adaptive and multi-threaded with backpressure support.
- Progress Tracking: Real-time updates with detailed metrics.
- Result Collection:
        Table Output: Pretty printed reports including curl PoC commands to reproduce the findings.
        JSON Output: Detailed JSON output saved to a file.
- Error Recovery: Automatic retries and recovery for transient errors.
- Concurrent Scans: Optimized resource use for parallel processing.

# 4. Payload Generators (Bypass Vectors)

Sophisticated payload generation system implementing various WAF/403 bypass techniques:

## Path Manipulation
- **Mid-path Injection**:
  - Injects payloads at each path segment
  - Supports both pre-slash and post-slash variants
  - Intelligent path structure preservation
  - Multiple injection points per URL
- **End-path Manipulation**:
  - Appends payloads to URL endpoints
   - Four variant strategies per payload:
     - url/suffix
     - url/suffix/
     - urlsuffix (for non-letter payloads)
     - urlsuffix/
 - Context-aware path joining
## Header Manipulation
- **IP-based Headers**:
   - Supports custom IP spoofing via CLI
   - Special handling for Forwarded header (by/for/host variants)
   - Support for custom Header & IP spoofing
- **Protocol Scheme Exploitation**:
   - HTTPS/SSL forcing headers
   - Protocol scheme variation
   - Special handling for Front-End-Https
   - Forwarded proto manipulation
- **URL/Port Headers**:
  - Parent path traversal variants
  - Full URL and path-only variants
  - Port-specific bypass attempts
  - Context-aware header selection
- **Host Header Attacks**:
   - IP-based variants using cached DNS results
   - Three attack vectors:
      - IP URL + Original Host header
      - Original URL + IP Host header
      - IP URL + No Host header
      - IPv4/IPv6 bypasses
## Content Manipulation
- **Case Substitution**:
  - Character-by-character case inversion
  - Preserves URL structure
  - Efficient duplicate prevention
- **Character Encoding**:
  - multiple encoding levels:
      - Single URL encoding
      - Double URL encoding
      - Triple URL encoding
  - Selective character encoding
  - Path structure preservation
## Debug & Reproducibility
 **Debug Token System**:
 - Unique fingerprint per payload generated/request sent
 - Compressed binary format
 - Stateless request tracking
 - Structure:
   - Version identifier
   - Random nonce (8 bytes)
   - URL data (length-prefixed)
   - Header data (count + entries)
 - Memory-efficient (<256 bytes typical)
 - Full request reproduction capability using the debug token of each request.
  
## Common Features
- URL structure preservation
- Efficient payload deduplication
- Memory-optimized generation
- Progress tracking and statistics
- Payload source file support
- CLI customization options

  
# 5. Raw HTTP Engine

Advanced request orchestration system featuring:

- Custom Worker Pool Architecture:
  - Efficient worker management with automatic scaling
  - Smart worker recycling and idle cleanup
  - Request batching and prioritization
  - Concurrent request executionckpressure control
- High-Performance HTTP Client:
   - Zero-allocation request building
   - Custom connection pooling
   - Direct socket manipulation
   - Raw HTTP request crafting without normalization
   - Malformed/ambiguous request support (RFC3986 violations)
- Memory Management:
   - Custom byte buffer pooling
   - Zero-copy operations where possible
   - Efficient buffer reuse strategies
   - Minimal allocation request construction
- Request Control:
  - Header manipulation without normalization
   - Raw path preservation
   - Direct payload injection
   - Custom protocol violations

# 6. Core Utilities

- Global Logger: Thread-safe, ANSI-colored output for clarity.
- Centralized Error Handling: Context-aware error propagation.
- Debugging System:
        Payload Tracking: Unique IDs for tracking requests.
        Reproducibility: Tokens to replay and debug specific requests.
    Metrics and Analysis: Collects performance data to inform optimizations.
Optimized Strings: Memory-efficient operations tailored for large datasets.

# 7. Testing Framework

Comprehensive self testing package.

 - Unit Tests:
    - Component-level validation
    - Edge case coverage
    - Error handling verification
  - Integration Tests:
    - End-to-end request flow testing
     - Protocol compliance verification
     - Bypass technique validation
  - Benchmarks:
    - Memory allocation profiling
     - Request throughput measurement
     - Worker pool efficiency testing
     - Buffer pool performance analysis
  - Parallel Testing:
    - Race condition detection
    - Concurrency stress testing
    - Resource contention analysis
- Mock Servers:
  - Echo servers for request validation
  - Malformed response testing
  - Protocol edge case simulation
