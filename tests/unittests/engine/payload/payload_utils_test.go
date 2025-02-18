package tests

import (
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
)

func TestURLConversions(t *testing.T) {
	tests := []struct {
		name          string
		inputURL      string
		method        string
		headers       []payload.Headers
		expectedJob   payload.BypassPayload
		expectedError bool
		roundTrip     bool // test if URL->Job->URL matches
	}{
		{
			name:     "Standard URL",
			inputURL: "https://example.com/path/to/resource",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path/to/resource",
			},
			roundTrip: true,
		},
		{
			name:     "URL with Unicode Path Separator",
			inputURL: "https://example.com/path／to／resource",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path/to/resource", // normalized
			},
			roundTrip: false, // will not match exactly due to normalization
		},
		{
			name:     "URL with Port",
			inputURL: "http://localhost:8080/api/v1",
			method:   "POST",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "POST",
				Scheme: "http",
				Host:   "localhost:8080",
				RawURI: "/api/v1",
			},
			roundTrip: true,
		},
		{
			name:     "URL with Query Parameters",
			inputURL: "https://api.example.com/search?q=test&page=1",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "api.example.com",
				RawURI: "/search",
			},
			roundTrip: false, // query params are stripped
		},
		{
			name:     "URL with Special Characters",
			inputURL: "https://example.com/path%20with%20spaces",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path%20with%20spaces",
			},
			roundTrip: true,
		},
		{
			name:          "Invalid URL",
			inputURL:      "not-a-url",
			method:        "GET",
			headers:       []payload.Headers{},
			expectedError: true,
		},
		{
			name:     "URL with Different Unicode Normalizations",
			inputURL: "https://example.com/café／test",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/café/test", // normalized
			},
			roundTrip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test FullURLToBypassPayload
			job, err := payload.FullURLToBypassPayload(tt.inputURL, tt.method, tt.headers)

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check job fields
			if job.Method != tt.expectedJob.Method {
				t.Errorf("Method mismatch: got %v, want %v", job.Method, tt.expectedJob.Method)
			}
			if job.Scheme != tt.expectedJob.Scheme {
				t.Errorf("Scheme mismatch: got %v, want %v", job.Scheme, tt.expectedJob.Scheme)
			}
			if job.Host != tt.expectedJob.Host {
				t.Errorf("Host mismatch: got %v, want %v", job.Host, tt.expectedJob.Host)
			}
			if job.RawURI != tt.expectedJob.RawURI {
				t.Errorf("RawURI mismatch: got %v, want %v", job.RawURI, tt.expectedJob.RawURI)
			}

			// Test round-trip if specified
			if tt.roundTrip {
				roundTripURL := payload.BypassPayloadToFullURL(job)
				if roundTripURL != tt.inputURL {
					t.Errorf("Round-trip mismatch:\ngot:  %v\nwant: %v", roundTripURL, tt.inputURL)
				}
			}
		})
	}
}

// TestNormalizationForms specifically tests the normalization function
func TestNormalizationForms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "NFKC Normalization",
			input:    "https://example.com/path／to／resource",
			expected: "https://example.com/path/to/resource",
			wantErr:  false,
		},
		{
			name:     "Mixed Unicode",
			input:    "https://example.com/café＋test",
			expected: "https://example.com/café+test",
			wantErr:  false,
		},
		{
			name:     "No Normalization Needed",
			input:    "https://example.com/normal/path",
			expected: "https://example.com/normal/path",
			wantErr:  false,
		},
		// Add more test cases based on your unicode_path_chars.lst
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := payload.TryNormalizationForms(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if normalized != tt.expected {
				t.Errorf("got %q, want %q", normalized, tt.expected)
			}
		})
	}
}
