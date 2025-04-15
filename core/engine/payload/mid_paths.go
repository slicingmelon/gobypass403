package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateMidPathsPayloads generates payloads by inserting mid-path segments from
internal_midpaths.lst around existing slashes in the base path.

For each slash, it creates variants by inserting the payload:
- Immediately after the slash (`/payload`).
- Immediately before the slash (`payload/`), only for slashes after the first one.

It also potentially adds variants prefixed with an additional leading slash.

If any generated path segment (before appending the original query) contains
literal '?' or '#' characters, additional payloads are generated where these
special characters are percent-encoded (%3F and %23) to ensure the original
query string can be appended unambiguously.
*/
func (pg *PayloadGenerator) GenerateMidPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_midpaths.lst") // Assumes this reads from the correct location
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads: %v", err)
		return jobs
	}

	basePath := parsedURL.Path // Path might contain raw '?' or '#'
	if basePath == "" {
		basePath = "/"
	}

	query := ""
	// Use Query as requested
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	slashCount := strings.Count(basePath, "/")
	// Treat paths without slashes (like "admin") as having one effective position for insertion relative to root.
	// However, ReplaceNth requires the separator '/' to exist.
	// If path is "admin", slashCount is 0. If path is "/admin", slashCount is 1. If path is "/", slashCount is 1.
	// The original loop `idxSlash < slashCount` means it won't run if path is "admin".
	// Let's adjust slightly: if path doesn't start with '/', consider insertions relative to a virtual root.
	effectivePathForReplace := basePath
	if !strings.HasPrefix(basePath, "/") && basePath != "" {
		effectivePathForReplace = "/" + basePath                 // Temporarily add slash for ReplaceNth
		slashCount = strings.Count(effectivePathForReplace, "/") // Recalculate slash count
	} else if basePath == "/" {
		slashCount = 1 // Ensure loop runs once for root path "/"
	}

	// map[rawURI]struct{} - using map for automatic deduplication
	uniquePaths := make(map[string]struct{})

	// Helper to add path and its special-char-encoded variant if necessary
	addPathVariants := func(pathCandidate string) {
		// Check if the path part contains special chars before query is appended
		pathContainsSpecial := strings.ContainsAny(pathCandidate, "?#")

		// Add the standard variant (path + query)
		uniquePaths[pathCandidate+query] = struct{}{}

		// If special chars exist in the path, add the encoded variant
		if pathContainsSpecial {
			encodedPath := encodePathSpecialChars(pathCandidate)
			uniquePaths[encodedPath+query] = struct{}{} // Add special char encoded variant
		}
	}

	// Iterate through each potential insertion point (slash position)
	// Note: ReplaceNth is 1-based for the 'n' parameter.
	for idxSlash := 1; idxSlash <= slashCount; idxSlash++ {
		for _, payload := range payloads {
			// --- Post-slash insertion: Replace Nth "/" with "/payload/" ---
			// We actually want to insert *after* the Nth slash, e.g., /admin/login -> /admin/payload/login
			// The original ReplaceNth(path, "/", "/"+payload, idxSlash+1) was replacing the (idxSlash+1)th occurrence,
			// which seems off. Let's rethink: Split path by '/', insert payload, rejoin.

			// Let's stick to ReplaceNth for now, assuming original intent was correct, but use the effective path.
			// Replace the idxSlash'th occurrence of "/" with "/" + payload + "/"
			// Example: /a/b/c, idxSlash=2 (second '/'). Replace "/b" with "/payload/b"? No.
			// ReplaceNth(path, "/", "/"+payload, idxSlash) -> replaces the idxSlash-th "/" with "/"+payload
			// e.g. /a/b/c, idxSlash=1 -> /payload/a/b/c - Incorrect
			// e.g. /a/b/c, idxSlash=2 -> /a/payload/b/c - Seems like the goal "insert after Nth slash"

			// Let's try replacing "/" with "/"+payload+"/" ? No, that adds slashes.
			// Replacing "/" with "/"+payload seems correct for *post*-slash insertion if we target the right index.
			// If we target the Nth slash (idxSlash), replacing it with "/"+payload gives insertion *before* the content following the Nth slash.

			// Post-slash: Replace the Nth "/" with "/" + payload
			pathPost := ReplaceNth(effectivePathForReplace, "/", "/"+payload, idxSlash)
			if pathPost != effectivePathForReplace { // Only add if replacement happened
				// Remove temporary leading slash if added earlier
				finalPathPost := pathPost
				if !strings.HasPrefix(basePath, "/") && strings.HasPrefix(pathPost, "/") {
					finalPathPost = strings.TrimPrefix(pathPost, "/")
				} else if basePath == "/" && finalPathPost == "/"+payload {
					// Handle root case: "/" -> ReplaceNth("/", "/", "/"+payload, 1) -> "/"+payload
					// Keep the leading slash here.
				} else if strings.HasPrefix(basePath, "//") && strings.HasPrefix(finalPathPost, "/") && !strings.HasPrefix(finalPathPost, "//") {
					// Preserve double slash if original had it. ReplaceNth might remove it.
					finalPathPost = "/" + finalPathPost
				}

				addPathVariants(finalPathPost)
				// Original code also added "/" + pathPost. Let's replicate that effect,
				// applying the same logic for trimming/adding slashes.
				// This seems intended to ensure a leading slash exists.
				prefixedPathPost := "/" + finalPathPost
				// Avoid triple slashes, etc.
				prefixedPathPost = strings.ReplaceAll(prefixedPathPost, "//", "/") // Basic normalization
				if strings.HasPrefix(prefixedPathPost, "/") {
					addPathVariants(prefixedPathPost)
				}

			}

			// --- Pre-slash insertion: Replace the Nth "/" with payload + "/" ---
			// Original code did this only if idxSlash > 1. Let's keep that.
			if idxSlash > 0 { // Condition simplified based on 1-based indexing
				pathPre := ReplaceNth(effectivePathForReplace, "/", payload+"/", idxSlash)
				if pathPre != effectivePathForReplace { // Only add if replacement happened
					// Remove temporary leading slash if added earlier
					finalPathPre := pathPre
					if !strings.HasPrefix(basePath, "/") && strings.HasPrefix(pathPre, "/") {
						finalPathPre = strings.TrimPrefix(pathPre, "/")
					} else if basePath == "/" && finalPathPre == payload+"/" {
						// Handle root case: "/" -> ReplaceNth("/", "/", payload+"/", 1) -> payload+"/"
						// This case probably shouldn't have leading slash? Or should be /payload/ ?
						// Let's assume /payload/ is intended for root pre-pend
						finalPathPre = "/" + payload + "/"
					} else if strings.HasPrefix(basePath, "//") && strings.HasPrefix(finalPathPre, "/") && !strings.HasPrefix(finalPathPre, "//") {
						finalPathPre = "/" + finalPathPre
					}

					addPathVariants(finalPathPre)
					// Add prefixed variant as well
					prefixedPathPre := "/" + finalPathPre
					prefixedPathPre = strings.ReplaceAll(prefixedPathPre, "//", "/") // Basic normalization
					if strings.HasPrefix(prefixedPathPre, "/") {
						addPathVariants(prefixedPathPre)
					}
				}
			}
		}
	}

	// Convert unique paths map to BypassPayload jobs
	for rawURI := range uniquePaths {
		// Ensure rawURI is not just the query string if path was empty
		if rawURI == query && query != "" {
			continue
		}
		// Ensure rawURI starts with / if the original basePath did, or if it was empty/root.
		// This corrects cases where ReplaceNth might remove a leading slash unintentionally.
		finalRawURI := rawURI
		if (strings.HasPrefix(basePath, "/") || basePath == "" || basePath == "/") && !strings.HasPrefix(rawURI, "/") {
			// Don't add slash if it's only the query part remaining somehow
			if !strings.HasPrefix(rawURI, "?") {
				finalRawURI = "/" + rawURI
			}
		}
		// Basic double slash cleanup, though fasthttp might handle this.
		finalRawURI = strings.ReplaceAll(finalRawURI, "//", "/")

		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET", // Consider making method configurable
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       finalRawURI, // Use the final, potentially corrected RawURI
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	// Log the total number of unique jobs created for this module
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
