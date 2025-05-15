# GoByPASS403

A powerful WAF (HTTP 403/401) and URL parser bypass tool developed in Go, designed to preserve exact URL paths and structures during testing. Unlike Go's standard libraries, the tool enables true raw HTTP requests without any encoding or normalization, ensuring complete control over the request structure. This functionality is powered by a full-stack HTTP client, independent of Go's internals, and a custom URL parser.

## Features

- **Raw URL Preservation**: Unlike other Go tools that use the standard `net/url` package which automatically normalizes and encodes URLs, Go-Bypass-403 preserves the exact URL structure similar to curl's `--path-as-is` flag. This is crucial for WAF bypass attempts where path traversal and specific URL structures need to be maintained.

- **Custom URL Parser**: Implements a specialized URL parser that prevents Go's default security measures from interfering with bypass attempts. This allows for testing of edge cases and security boundaries that would otherwise be normalized away.

- **Multiple Bypass Techniques**: 
  - Path manipulation (mid-path, end-path)
  - Case substitution
  - Headers manipulation (IP, scheme, URL, port)
  - Character encoding variations
  - And more...

- **CDN Bypass Support**: Special features for testing CDN-based bypasses using host substitution

# Precompiled Binaries

- Windows, Linux and MacOS builds available: https://github.com/slicingmelon/gobypass403/releases/latest

# Build

```bash
git clone https://github.com/slicingmelon/gobypass403.git
go get
go build .\cmd\gobypass403\
```

# Usage

```
GoByPASS403

Usage:
  -u, -url
        Target URL (example: https://cms.facebook.com/login)
  -l, -urls-file
        File containing list of target URLs (one per line)
  -shf, -substitute-hosts-file
        File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)
  -m, -module
        Bypass module (all,path_prefix,mid_paths,end_paths,http_methods,case_substitution,char_encode,nginx_bypasses,unicode_path_normalization,headers_scheme,headers_ip,headers_port,headers_url,headers_host) (Default: all)
  -o, -outdir
        Output directory
  -cr, -concurrent-requests
        Number of concurrent requests (Default: 15)
  -T, -timeout
        Total timeout (in milliseconds) (Default: 20000)
  -delay
        Delay between requests (in milliseconds) (0 means no delay) (Default: 0)
  -max-retries
        Maximum number of retries for failed requests (0 means no retries) (Default: 2)
  -retry-delay
        Delay between retries (in milliseconds) (Default: 500)
  -max-cfr, -max-consecutive-fails
        Maximum number of consecutive failed requests before cancelling the current bypass module (Default: 15)
  -at, -auto-throttle
        Enable automatic request throttling (on/off, 1/0) (Default: on)
  -v, -verbose
        Verbose output (Default: false)
  -d, -debug
        Debug mode with request canaries (Default: false)
  -mc, -match-status-code
        Filter results by HTTP status codes (example: -mc 200, 301, 5xx, all). Default: All status codes
  -mct, -match-content-type
        Filter results by content type(s) substring (example: -mct application/json,text/html)
  -min-cl, -min-content-length
        Filter results by minimum Content-Length (example: -min-cl 100)
  -max-cl, -max-content-length
        Filter results by maximum Content-Length (example: -max-cl 5000)
  -http2
        Enable HTTP2 client (Default: false)
  -x, -proxy
        Proxy URL (format: http://proxy:port) (Example: -x http://127.0.0.1:8080)
  -spoof-header
        Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)
  -spoof-ip
        Add more spoof IPs (example: 10.10.20.20,172.16.30.10)
  -fr, -follow-redirects
        Follow HTTP redirects
  -rbps, -response-body-preview-size
        Maximum number of bytes to retrieve from response body (Default: 1024)
  -drbs, -disable-response-body-streaming
        Disables streaming of response body (default: False) (Default: false)
  -dpb, -disable-progress-bar
        Disable progress bar (Default: false)
  -r, -resend
        Resend the exact request using the debug token (example: -r xyzdebugtoken)
  -rn, -resend-num
        Number of times to resend the debugged request (Default: 1)
  -profile
        Enable pprof profiler (Default: false)
  -update-payloads
        Update payload files to latest version (Default: false)
```

## Standard WAF 403/401 Bypass

Standard command(s):
```bash
gobypass403 -u "https://go-test-webapp.com/admin" -mc "200"
gobypass403 -u "https://go-test-webapp.com/admin" -mc "200,500" -cr 10
gobypass403 -u "https://go-test-webapp.com/admin" -mc "mid_paths,nginx_bypasses,headers_ip" -cr 20 -mct "application/json,image/png"
```

Using a list of target URLs:
```bash
gobypass403 -l "targeturls.txt" 
```

## Find CDN Bypasses Using A List Of Hosts 

Sometimes you want to find bypasses in a long list of CDNs, and you know that the video path is always the same. Example when you want to bypass the hash check on a video or image.

// Redacted. Will update.

## Screenshots

Example Results 1
![Screenshot 1](images/1.jpg)

# Bypass Modules

Some description..

## char_encode

The `char_encode` module implements targeted character encoding techniques to bypass WAF pattern matching. It systematically generates payloads by applying URL encoding to specific characters in the path.

The module works on four strategic positions:

- Last character of the path
- First character after any leading slash
- Each character in the last path segment
- Each character throughout the entire path

For each position, it generates:
- Single encoding (`%xx`)
- Double encoding (`%25xx`)
- Triple encoding (`%2525xx`)

For example, with a URL like `https://example.com/admin`:

```
/admin → /admi%6e          # Last character encoded
/admin → /%61dmin          # First character encoded  
/admin → /adm%69n          # Character in path encoded
```

Special characters like `?` and `#` are handled with proper percent-encoding to preserve query parameters.

## mid_paths

The `mid_paths` module injects path traversal sequences and special character combinations using a predefined list of payloads (`internal_midpaths.lst`).

For a URL like `/a/b`, the module creates these variants:

1. Before path:
   - `PAYLOAD/a/b`
   - `/PAYLOAD/a/b`

2. At each segment:
   - `/PAYLOADa/b` (fused with first segment start)
   - `/aPAYLOAD/b` (fused with first segment end)
   - `/a/PAYLOADb` (fused with second segment start)
   - `/a/bPAYLOAD` (fused with second segment end)

3. After each slash:
   - `/a/PAYLOAD/b` (inserted after a slash)

Each variant is generated with appropriate path normalization handling. The module carefully manages special characters in path segments, generating additional variants with percent-encoded `?` and `#` characters when necessary.

## end_paths 

The `end_paths` module appends a variety of suffixes from a predefined list (`internal_endpaths.lst`) to the end of the URL path. This technique targets path normalization vulnerabilities and extension handling issues in WAFs.

For a URL like `https://example.com/admin`, the module generates:

1. Standard suffix variants:
   - `/admin/SUFFIX`
   - `/admin/SUFFIX/`

2. Direct append variants (when the base path isn't root `/` and suffix doesn't start with a letter):
   - `/adminSUFFIX`
   - `/adminSUFFIX/`

Common suffixes include:
- Path traversal sequences: `..;/`, `../`, `./`
- Special characters: `;`, `:`, `%20`
- Common extensions: `.json`, `.php~`, `.bak`

The module preserves the original query string and handles special characters with proper percent-encoding to maintain request integrity.

## path_prefix

The `path_prefix` module manipulates path segments using specific byte patterns to bypass security checks. It systematically prefixes URL segments with ASCII control characters, special characters, and the literal 'x' character.

For each relevant byte value, the module creates three distinct variations:

1. Dummy Segment Prefix (Single Byte):
   - Adds a new first segment containing the byte value
   - Example: `/admin` → `/[b1]/admin` or `/%XX/admin`

2. Existing Segment Prefix (Single Byte):
   - Prepends the byte to each existing segment individually
   - Example: `/admin/login` → `/[b1]admin/login` or `/%XXadmin/login`

3. Existing Segment Prefix (Two Bytes):
   - Prepends byte pairs to each existing segment
   - Example: `/admin/login` → `/[b1b2]admin/login` or `/%XX%YYadmin/login`

Each byte value is applied both as a raw byte (when safe) and in percent-encoded form to ensure maximum coverage of potential bypass vectors.

## http_methods 

The `http_methods` module tests various standard and non-standard HTTP methods loaded from a predefined list (`internal_http_methods.lst`). HTTP method switching is a well-known technique to bypass WAF rules that only filter specific methods.

For each method, it generates:

1. Base method variation:
   - Uses the specified method with the original URL's path and query string
   - Example: `OPTIONS /admin` instead of `GET /admin`

2. Content-Length handling:
   - For methods that typically expect a body (POST, PUT, PATCH, DELETE), adds `Content-Length: 0` header
   - Example: `DELETE /admin` with `Content-Length: 0`

3. Query parameter relocation (POST only):
   - For POST requests with query parameters, creates a variant where:
     - Query string is removed from URL
     - Parameters are moved to the request body
     - Proper content type headers are set
   - Example: `POST /admin?id=1` becomes `POST /admin` with body `id=1`

## case_substitution 

The `case_substitution` module applies targeted case manipulations to bypass case-sensitive pattern matching in WAFs and ACLs.

It implements four distinct case manipulation strategies:

1. Terminal character case inversion:
   - Uppercases only the last letter of the path (if lowercase)
   - Example: `/admin` → `/admiN`

2. HTTP method case manipulation:
   - Uppercases the HTTP method (e.g., "GET", "POST")
   - Example: `get /admin` → `GET /admin`

3. Character-by-character case inversion:
   - Inverts the case of each letter in the path individually
   - Example: `/admin` → `/Admin`, `/aDmin`, `/adMin`, `/admIn`, etc.

4. Full path uppercase conversion:
   - Uppercases the entire path string
   - Example: `/admin` → `/ADMIN`

All original query parameters are preserved when applying these case manipulations.

## nginx_bypasses

The `nginx_bypasses` module is a comprehensive collection of techniques targeting server-side parsing inconsistencies across multiple web frameworks and server types. While named for Nginx, it targets a broad spectrum of platforms including Flask, Spring Boot, and Node.js applications.

The module implements several specialized bypass vectors:

1. Framework-specific byte patterns:
   - Flask bypasses: Uses special bytes (0x85, 0xA0, 0x1F, 0x1E, 0x1D, 0x1C, 0x0C, 0x0B) that can trigger path normalization bugs
   - Spring Boot bypasses: Leverages tab character (0x09) and semicolon (;) interpretation quirks
   - Node.js bypasses: Exploits specific characters (0xA0, 0x09, 0x0C) that Node.js processes differently

2. Strategic character insertion:
   - Inserts both raw and percent-encoded special bytes at six critical positions:
     - Path end: `/admin[char]`
     - After trailing slash: `/admin/[char]`
     - Path beginning: `/[char]admin`
     - After each segment: `/segment1[char]/segment2`
     - Before each segment: `/segment1/[char]segment2`
     - After first character: `/s[char]egment1`

3. Request splitting techniques:
   - HTTP protocol confusion with newlines: 
     - Injects `%0A` followed by HTTP version strings (`HTTP/1.1`, `HTTP/1.0`, `HTTP/2.0`, `HTTP/0.9`)
     - Example: `/admin%0AHTTP/1.1`

4. Routing manipulation attacks:
   - Complex request smuggling vectors:
     - Combines newlines, HTTP versions, and alternative URIs
     - Example: `/admin%0AHTTP/1.1%0Ahttp://localhost/admin`
   - Host variation:
     - Tests multiple alternative hosts: `localhost`, `127.0.0.1` with different port combinations
     - Combines with explicit Host header manipulation

5. Protocol handler exploitation:
   - Tests different URI schemes (`http://`, `https://`, `file://`, `gopher://`)
   - Targets proxy pass-through vulnerabilities and protocol handler misconfigurations

The module represents one of the most comprehensive path manipulation testing suites, targeting inconsistencies in:
- HTTP request parsing
- Proxy handling
- Framework-specific path normalization
- Reverse proxy configurations
- Load balancer behavior
- Server-side protocol handling

Each payload is carefully generated to preserve proper URL structure and ensure the original query parameters are correctly maintained.

## unicode_path_normalization 

The `unicode_path_normalization` module generates denormalized Unicode payloads specifically targeting systems that perform Unicode normalization during request processing. Rather than exploiting normalization inconsistencies directly, it creates payloads that appear benign before normalization but transform into bypass vectors after normalization occurs.

Key techniques include:

1. Denormalized character sequences:
   - Deliberately uses Unicode characters that normalize to restricted ASCII characters
   - Example: Sending a decomposed form that normalizes to `/admin` on the server side

2. Bidirectional text manipulation:
   - Inserts right-to-left override characters that may be stripped during normalization
   - Can cause WAFs to interpret paths differently than application servers

3. Homoglyph substitution:
   - Uses visually similar but different Unicode code points
   - Target systems normalize these to standard ASCII, bypassing pattern matching
   - Example: Cyrillic 'а' (U+0430) vs ASCII 'a' (U+0061) which appear identical but have different code points

4. Normalization form exploitation:
   - Leverages differences between NFC, NFD, NFKC, and NFKD normalization forms
   - Creates payloads in one form that transform to another form after processing
   - Targets systems where WAF and application server use different normalization forms

This module is particularly effective against multi-tiered architectures where different components (load balancers, WAFs, application servers) handle Unicode normalization differently, creating security gaps between the initial request validation and final request processing.

## headers_scheme 

The `headers_scheme` module tests protocol-based bypasses using custom HTTP headers that indicate the original protocol or request scheme. Many applications rely on these headers for internal routing decisions and security policies.

The module operates by:

1. Reading two predefined lists:
   - `header_proto_schemes.lst`: Common headers for protocol indication
   - `internal_proto_schemes.lst`: Various protocol schemes to test (http, https, etc.)

2. Generating scheme-based payloads in three categories:
   - Standard protocol indicators: Pairs most headers with each protocol scheme
   - HTTPS-specific flags: Sets headers like `Front-End-Https`, `X-Forwarded-HTTPS`, and `X-Forwarded-SSL` to `on`
   - Forwarded header (RFC 7239): Uses the standardized format `proto={scheme}`

These headers exploit common misconfigurations in:
- Reverse proxies that don't properly validate or sanitize forwarded scheme information
- Load balancers that trust scheme headers for SSL/TLS decisions
- Web applications that use scheme headers for conditional logic or URL construction

## headers_ip

The `headers_ip` module is a powerful IP spoofing toolkit that exploits how servers trust client-reported IP addresses for access control decisions. This often-overlooked bypass technique can circumvent WAF restrictions by manipulating IP-based trust relationships.

Key capabilities include:

1. Comprehensive header coverage:
   - Tests all industry-standard IP reporting headers:
     - `X-Forwarded-For`: The de-facto standard for client IP behind proxies
     - `X-Real-IP`: Used by Nginx and many CDNs for original client IP
     - `X-Client-IP`: Common in enterprise environments
     - `X-Originating-IP`: Used by Microsoft products and services
     - Dozens of additional vendor-specific headers from `header_ip_hosts.lst`

2. Multi-source IP data collection:
   - Dynamic IP reconnaissance at runtime - automatically caches all resolved IPs, CNAMEs, and DNS records
   - Predefined IP address lists from `internal_ip_hosts.lst` targeting internal/trusted networks
   - Custom IP specification via `-spoof-ip` CLI flag (comma-separated values)
   - Focus on high-value targets: localhost, internal networks, cloud metadata IPs

3. Advanced header manipulation:
   - Custom header support via `-spoof-header` CLI flag for targeting specific environments
   - Tests both original and normalized (canonicalized) forms of headers
   - RFC 7239 Forwarded header with parameter variations: `by=`, `for=`, and `host=`
   - Special-case bypasses like `X-AppEngine-Trusted-IP-Request: 1`

This technique exploits fundamental architectural weaknesses in:
- Multi-tier architectures where trust is established between components
- IP-based access control lists (ACLs) for admin interfaces
- Cloud environments that trust specific internal IPs
- WAFs that exempt traffic from certain source addresses
- Load balancers that make routing decisions based on client IP

## headers_port

The `headers_port` module manipulates port-related HTTP headers to bypass security controls that make routing or access decisions based on the originating port.

The module works by:

1. Reading from two predefined lists:
   - `header_ports.lst`: Various HTTP headers that may carry port information
   - `internal_ports.lst`: Collection of port numbers to test, including standard web ports, common alternative ports, and privileged ports

2. Generating comprehensive combinations:
   - Pairs each header name with each port number
   - Preserves the original URL structure (scheme, host, path, query string)

This technique targets systems that:
- Apply different security rules based on the client's source port
- Trust port headers for internal routing decisions
- Have port-based ACL rules that can be bypassed with header manipulation

## headers_url

The `headers_url` module implements URL path injection techniques through custom headers, targeting web applications and proxies that use header values for internal routing.

The module employs several sophisticated approaches:

1. Path injection with root traversal:
   - Sets the request path to `/` while placing the actual target path in headers
   - Loads header names from `header_urls.lst` (X-Original-URL, X-Rewrite-URL, etc.)
   - Variations include base path alone or with query parameters

2. Parent path traversal:
   - Systematically tests all parent directories of the target path
   - Example: For `/a/b/c`, tries `/a/b`, `/a`, and `/` in headers
   - Each parent path is tested both with and without query string

3. Full URL injection:
   - For headers containing "url", "request", or "refer" in their name
   - Injects complete URLs (scheme://host/path) with variants of the path
   - Tests both with and without query parameters

4. CVE-2025-29927 exploitation:
   - Targets Next.js middleware bypass via `x-middleware-subrequest` header
   - Tests values like `middleware`, `middleware:middleware`, up to 7 repetitions
   - Includes variants with `src/middleware` prefix for comprehensive coverage

This module is particularly effective against misconfigured reverse proxies, rewrite engines, and web frameworks that prioritize header-specified paths over the actual request URI.

## headers_host

The `headers_host` module exploits discrepancies between URL hostname and Host header processing, leveraging real-time reconnaissance data to generate targeted bypass attempts.

Key features include:

1. Dynamic reconnaissance integration:
   - Utilizes the tool's built-in recon cache that collects IP addresses and CNAMEs for target hosts
   - Automatically generates payloads based on discovered network topology
   - Supports both IPv4 and IPv6 address variations

2. IPv4/IPv6 service variations:
   - For each discovered IP (with scheme and port):
     - Uses IP as URL host with original hostname in Host header
     - Uses original hostname in URL with IP in Host header
   - Handles port specifications appropriately (default ports vs. explicit ports)
   - Creates IPv6-specific variants with proper bracket notation ([IPv6]:port)

3. CNAME-based bypass techniques:
   - Uses discovered canonical names from DNS reconnaissance
   - Four strategic variations for each CNAME:
     - Original URL + CNAME in Host header
     - CNAME as URL host + original hostname in Host header
     - CNAME in both URL host and Host header
     - Recursive domain suffix testing (e.g., sub.domain.com → domain.com)

This module is especially powerful for:
- Content Delivery Network (CDN) bypass attempts
- Virtual host confusion attacks
- DNS-based access control evasion
- Load balancer and reverse proxy misconfigurations

# Changelog

## 0.7.9

- Updated all unit tests.
- Each bypass module now has its own deduplication algorithm.
- Added a global deduplication component that filters bypass modules to ensure the same payload is not sent more than once across different modules.
- Refactored `mid_paths` module entirely - it now generates payloads more efficiently, bypass coverage increased as well. 
- Updated payloads lists for `mid_paths` and `end_paths` modules.
- Fixed a major bug when scanning a list of URLs using the `-l` CLI command.
- Updated SQLite DB schema and table organization for better performance.
- Updated GitHub workflow - Linux builds are now compatible with older libc versions.


## 0.7.8

- Updated internal HTTP client to fasthttp 1.62.0. All gobypass403 patches applied.
- Added CVE-2025-29927 bypass, via `x-middleware-subrequest`.
- Proper unit-tests for most of the bypass modules.
- Payload files version detection. Updated the `-update-payloads` CLI command.
- Important updates on the final output table. The results table now includes only a summary of the findings, up to 5 unique results, sorted per url -> bypass module -> status code -> number of bytes in the HTTP response. 
- New CLI options:
  - `-mct, -match-content-type` Filter results by content type(s) substring (example: -mct application/json,text/html)
  - `-min-cl, -min-content-length` Filter results by minimum Content-Length (example: -min-cl 100).
  - `-max-cl, -max-content-length`  Filter results by maximum Content-Length (example: -max-cl 5000).
- Modular bypass modules. Each bypass module has its own .go file. 
- New bypass modules: `nginx_bypasses`, `unicode_path_normalization`, `path_prefix`.
- All bypass modules generating unicode/reverse unicode normalization payloads now rely on a pre-built charmap available in the payloads directory.  
- Updated support for `Transfer-Encoding: identity` HTTP responses.
- Several code refactors, including performance updates.
- New, fully refactored, progressbar. 

## 27 March 2025

- Major release.

## 14 February 2025

- Implemented retry attempts on failed requests, using linear backoff algorithm to increase the delay between retries.
- Autothrottler, throttles the requests exponentially based on known status codes.
- Option to resend the exact request at any time using the debug token.
- Refactored most of the core engine/rawhttp modules to improve performance and reduce allocations.
- Plus way more improvements...

## 09 January 2025

- Refactored the entire codebase. Everything will be documented separately. 

## 05 November 2024

- First official release


## Motivation

Traditional Go-based security tools often struggle with WAF bypasses because Go's standard libraries are designed to be secure by default, automatically normalizing URLs and encoding special characters. This makes it difficult to test certain types of bypasses that rely on specific URL structures or character sequences.

Go-Bypass-403 solves this by:
1. Using a custom URL parser that preserves raw paths
2. Implementing curl-like path preservation
3. Maintaining exact URL structures throughout the testing process
4. Allowing for true raw URL manipulation without automatic sanitization
5. The best similar tool that is publicly available was developed by [laluka](https://github.com/laluka) and can be found at the following URL: [bypass-url-parser](https://github.com/laluka/bypass-url-parser). It is written in Python, however, it uses curl for each bypass attempt, as curl supports `--path-as-is` to send raw payloads. Unfortunately, this tool is extremely slow because it uses curl to send the requests.
Quote from laluka:
> If you wonder why this code is nothing but a dirty curl wrapper, here's why:
>>    Most of the python requests do url/path/parameter encoding/decoding, and I hate this.
>>    If I submit raw chars, I want raw chars to be sent.
>>    If I send a weird path, I want it weird, not normalized.
>>
>This is surprisingly hard to achieve in python without losing all of the lib goodies like parsing, ssl/tls encapsulation and so on.
So, be like me, use curl as a backend, it's gonna be just fine.

### Credits


This tool was inspired by and based on [laluka's bypass-url-parser](https://github.com/laluka/bypass-url-parser). All credit for the original concept and bypass techniques goes to him.

Special thanks to [laluka](https://github.com/laluka) for open-sourcing his work and his vast bypass techniques implemented in his tool.

