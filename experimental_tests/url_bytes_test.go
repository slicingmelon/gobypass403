package experimentaltests

import (
	"bytes"
	"testing"
)

func TestRawURLParseBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
		wantURL *RawURLBytes
	}{
		{
			name:    "empty url",
			input:   "",
			wantErr: ErrEmptyURL,
		},
		{
			name:  "simple domain",
			input: "https://example.com",
			wantURL: &RawURLBytes{
				Scheme: []byte("https"),
				Host:   []byte("example.com"),
				Path:   []byte("/"),
			},
		},
		{
			name:  "with path",
			input: "https://example.com/path/to/resource",
			wantURL: &RawURLBytes{
				Scheme: []byte("https"),
				Host:   []byte("example.com"),
				Path:   []byte("/path/to/resource"),
			},
		},
		{
			name:  "with port",
			input: "http://example.com:8080/path",
			wantURL: &RawURLBytes{
				Scheme: []byte("http"),
				Host:   []byte("example.com:8080"),
				Path:   []byte("/path"),
			},
		},
		{
			name:  "with query",
			input: "https://example.com/path?key=value&foo=bar",
			wantURL: &RawURLBytes{
				Scheme: []byte("https"),
				Host:   []byte("example.com"),
				Path:   []byte("/path"),
				Query:  []byte("key=value&foo=bar"),
			},
		},
		{
			name:  "with fragment",
			input: "https://example.com/path#section1",
			wantURL: &RawURLBytes{
				Scheme:   []byte("https"),
				Host:     []byte("example.com"),
				Path:     []byte("/path"),
				Fragment: []byte("section1"),
			},
		},
		{
			name:  "IPv4",
			input: "http://127.0.0.1/path",
			wantURL: &RawURLBytes{
				Scheme: []byte("http"),
				Host:   []byte("127.0.0.1"),
				Path:   []byte("/path"),
			},
		},
		{
			name:  "IPv4 with port",
			input: "http://127.0.0.1:8080/path",
			wantURL: &RawURLBytes{
				Scheme: []byte("http"),
				Host:   []byte("127.0.0.1:8080"),
				Path:   []byte("/path"),
			},
		},
		{
			name:  "IPv6",
			input: "http://[2001:db8::1]/path",
			wantURL: &RawURLBytes{
				Scheme: []byte("http"),
				Host:   []byte("[2001:db8::1]"),
				Path:   []byte("/path"),
			},
		},
		{
			name:  "IPv6 with port",
			input: "http://[2001:db8::1]:8080/path",
			wantURL: &RawURLBytes{
				Scheme: []byte("http"),
				Host:   []byte("[2001:db8::1]:8080"),
				Path:   []byte("/path"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RawURLParseBytes([]byte(tt.input))

			// Always print the result, but handle nil case
			resultMap := map[string]string{
				"Scheme":   "",
				"Host":     "",
				"Path":     "",
				"Query":    "",
				"Fragment": "",
			}

			if got != nil {
				resultMap = map[string]string{
					"Scheme":   string(got.Scheme),
					"Host":     string(got.Host),
					"Path":     string(got.Path),
					"Query":    string(got.Query),
					"Fragment": string(got.Fragment),
				}
			}

			t.Logf("\nTest: %s\nInput: %q\nError: %v\nResult: %+v\n",
				tt.name,
				tt.input,
				err,
				resultMap,
			)

			// Check error
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("RawURLParseBytes() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("RawURLParseBytes() unexpected error: %v", err)
				return
			}

			// Check fields and print comparison
			if !bytes.Equal(got.Scheme, tt.wantURL.Scheme) {
				t.Errorf("Scheme = %q, want %q", string(got.Scheme), string(tt.wantURL.Scheme))
			}
			if !bytes.Equal(got.Host, tt.wantURL.Host) {
				t.Errorf("Host = %q, want %q", string(got.Host), string(tt.wantURL.Host))
			}
			if !bytes.Equal(got.Path, tt.wantURL.Path) {
				t.Errorf("Path = %q, want %q", string(got.Path), string(tt.wantURL.Path))
			}
			if !bytes.Equal(got.Query, tt.wantURL.Query) {
				t.Errorf("Query = %q, want %q", string(got.Query), string(tt.wantURL.Query))
			}
			if !bytes.Equal(got.Fragment, tt.wantURL.Fragment) {
				t.Errorf("Fragment = %q, want %q", string(got.Fragment), string(tt.wantURL.Fragment))
			}
		})
	}
}
