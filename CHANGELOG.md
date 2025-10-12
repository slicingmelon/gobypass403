# 0.8.7 (Unreleased)

- **Updated `unicode_path_experimental`** module - Advanced Unicode confusable-based WAF bypass
  - Exploits Unicode normalization vulnerabilities by systematically substituting ASCII characters with visually similar Unicode lookalikes (confusables).
  - Attack vector: WAF sees Unicode characters (e.g., `/admin․․/` using U+2024), backend normalizes to ASCII (e.g., `/admin../`), allowing bypass.
  - Generates ~75K payloads with `maxNormalizationsExperimental=2`, ~150K+ with `maxNormalizationsExperimental=5`.
  - One-character-at-a-time substitution strategy maximizes test coverage.
  - Doubles each variant: generates both raw Unicode and fully URL-encoded versions (`․.;` → raw + `%E2%80%A4.%3B`).
  - Byte-based UTF-8 processing using `utf8.DecodeRune`/`EncodeRune` for efficiency and correctness.
  - Preserves percent-encoded sequences (%XX) during substitution to avoid breaking existing encoding.
  - Integrates with `mid_paths` generation logic for comprehensive path manipulation techniques.
  - Uses `unicode_normalization_map.json` for ASCII→Unicode lookalike mappings.
  - Global deduplication prevents payload overlap with standard `mid_paths` module.

- **Fixed `end_paths`** module - Corrected alphanumeric detection for direct concatenation
  - Changed condition from `!isLetterASCII(payload[0])` to `!isAlphanumericASCII(payload[0])`.
  - Now properly prevents nonsensical concatenations for both words AND digits.
  - Prevents `/admin/login` + `0` → `/admin/login0` (nonsense).
  - Prevents `/admin/login` + `debug` → `/admin/logindebug` (nonsense).
  - Still allows `/admin/login` + `.css` → `/admin/login.css` (file extension bypass).
  - Ensures digits (`0`, `1`) are treated the same as words when appending to paths.
  - Added 20 new payloads to `internal_endpaths.lst`: encoded dots (`.%2e`, `%2e%2e%2f`), whitespace+slash combinations (`%09/`, `%20/`), and complex traversal patterns (`;%2f..%2f..%2f`, `..%3B/`).

- **Refactored `char_encode`** module - Consistent byte-wise iteration for URL encoding
  - Replaced mixed byte/rune iteration patterns with uniform byte-wise iteration throughout.
  - All encoding operations now use byte-level processing (`for i := 0; i < len(s); i++`) for ASCII letter detection.
  - Removed fragile rune-based range loops that could break with multi-byte UTF-8 (though current logic prevented this).
  - Changed `strings.Builder.WriteRune()` to `WriteByte()` for ASCII-only character handling.
  - Maintains identical functionality while improving code consistency and clarity.
  - Aligns with the tool's byte-oriented raw HTTP request architecture.
  
- **Performance optimization: `URLEncodeAll` function**
  - Refactored to use zero-copy string indexing instead of intermediate `[]byte` allocation.
  - Direct byte access via `s[i]` eliminates full string-to-byte-slice conversion overhead.
  - Pre-allocated exact buffer size (3 bytes per input byte) for optimal memory usage.
  - Removed repeated `append()` calls in favor of direct indexing (eliminates bounds checking overhead).
  - Properly handles UTF-8 characters by encoding each byte of their UTF-8 representation.

# 0.8.6

- Fixed critical deduplication bug in `nginx_bypasses` module where payloads with identical URIs but different headers were being dropped. Deduplication now uses composite key (RawURI + Headers) to preserve header variations, resulting in ~74% more test cases for comprehensive bypass testing.
  
# 0.8.5

- Added new CLI parameter `-strict-scheme` to perform testing only on the original scheme.
- Updated `headers_urls` payloads.
- The tool is now using a full, idependent, modified fasthttp client, completely stripped from any code unrelated to the client's comopnenets. 
- Also updated the internal fasthttp client to 1.64.0.
- New CLI option -em/-exclude-module.
- `-m` and `-em` now support glob patterns with *.
- Updated `internal_midpaths.lst` payloads.
- Updated internal tool `unicode_normalization_map.go`.
- Replaced internal `unicode_char_map.json` with `unicode_normalization_map.json`.
- Added a new tool `unicode_truncation_map.go`.
- Updated `unicode_path_normalization` module.
- Updated `char_encode` module.
- New bypass module `haproxy_bypasses`, two CVEs included:
  - CVE-2021-40346: HTTP Request Smuggling via Integer Overflow
  - CVE-2023-45539: URL Fragment ACL Bypass
- New bypass module `unicode_path_truncation`.
  - Targets applications that perform byte-level truncation (`char & 0xFF`) on Unicode characters.
  - Includes prebuilt `unicode_truncation_map.json` with comprehensive character mappings for all bytes (0x00-0xFF).
    
# 0.8.3-0.8.4

- Updated Github Actions workflow, linux static builds are done in Alpine with musl. Fixing issue [#1](https://github.com/slicingmelon/gobypass403/issues/1).
- Updated default output dir to `/tmp/gobypass403_tmp/` instead of `/tmp/`.
- Pre-compiled release binaries now include the version in the filename.
- Updated .goreleaser.yml just for local dev/snapshot builds.
- Updated README.

# 0.8.2

- Updated README.
- Small refactoring.
 
# 0.8.1

- Updated go to 1.24.1.
- Increased TLS LRUSessionCache size.
- Now using custom go-bytesutil pkgs.
- Public repo from now on.

# 0.8.0

- Major update.
- New module haproxy_bypasses.
- Bypass attempts using request smuggling (haproxy CVE).
- Multiple code optimizations.
- Documentation updated on the main README.md file.

# 0.7.9

- Updated all unit tests.
- Each bypass module now has its own deduplication algorithm.
- Added a global deduplication component that filters bypass modules to ensure the same payload is not sent more than once across different modules.
- Refactored `mid_paths` module entirely - it now generates payloads more efficiently, bypass coverage increased as well. 
- Updated payloads lists for `mid_paths` and `end_paths` modules.
- Fixed a major bug when scanning a list of URLs using the `-l` CLI command.
- Updated SQLite DB schema and table organization for better performance.
- Updated GitHub workflow - Linux builds are now compatible with older libc versions.


# 0.7.8

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

# 27 March 2025

- Major release.

# 14 February 2025

- Implemented retry attempts on failed requests, using linear backoff algorithm to increase the delay between retries.
- Autothrottler, throttles the requests exponentially based on known status codes.
- Option to resend the exact request at any time using the debug token.
- Refactored most of the core engine/rawhttp modules to improve performance and reduce allocations.
- Plus way more improvements...

# 09 January 2025

- Refactored the entire codebase. Everything will be documented separately. 

# 05 November 2024

- First official release