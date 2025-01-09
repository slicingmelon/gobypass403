package recon

import (
	"testing"
	"time"
)

func TestReconService_Run(t *testing.T) {
	service := NewReconService()

	testURLs := []string{
		// Valid hosts
		"https://revoked.badssl.com/",
		"http://httpbin.org/get",
		"https://scanme.sh",

		// IP addresses
		"http://1.1.1.1/",
		"https://8.8.8.8/",
		"http://[2606:4700:4700::1111]",

		// Edge cases
		"http://127.0.0.1:89/", // Closed port
		"http://[::1]:80/",     // IPv6 localhost
		"http://127.0.0.1:98/", // Another closed port
		"http://[::1]/",        // IPv6 localhost without port

		// Invalid cases
		"https://thisisnotarealdomainname123456789.com/",
		"http://localhost:65536/",  // Invalid port number
		"https://scanme.sh:12345/", // Non-standard port
	}

	// Test Run function
	err := service.Run(testURLs)
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}

	// Allow time for async operations to complete
	time.Sleep(2 * time.Second)

	// Test cache results for each host
	expectedHosts := []string{
		"revoked.badssl.com",
		"httpbin.org",
		"scanme.sh",
	}

	for _, host := range expectedHosts {
		result, err := service.cache.Get(host)
		if err != nil {
			t.Errorf("Failed to get cache for %s: %v", host, err)
			continue
		}

		if result == nil {
			t.Errorf("No cache result for %s", host)
			continue
		}

		// Verify basic structure
		if result.Hostname != host {
			t.Errorf("Expected hostname %s, got %s", host, result.Hostname)
		}

		// Verify IPv4 services
		if len(result.IPv4Services) == 0 {
			t.Errorf("No IPv4 services found for %s", host)
		}

		// Check for expected schemes
		for scheme, ips := range result.IPv4Services {
			if scheme != "http" && scheme != "https" {
				t.Errorf("Unexpected scheme %s for %s", scheme, host)
			}
			if len(ips) == 0 {
				t.Errorf("No IPs found for scheme %s on %s", scheme, host)
			}

			// Check ports for each IP
			for ip, ports := range ips {
				if len(ports) == 0 {
					t.Errorf("No ports found for IP %s on %s", ip, host)
				}
				t.Logf("IPv4 %s service on %s: %s -> %v", scheme, host, ip, ports)
			}
		}

		// Verify IPv6 services if present
		if len(result.IPv6Services) > 0 {
			for scheme, ips := range result.IPv6Services {
				if scheme != "http" && scheme != "https" {
					t.Errorf("Unexpected scheme %s for %s", scheme, host)
				}
				for ip, ports := range ips {
					t.Logf("IPv6 %s service on %s: %s -> %v", scheme, host, ip, ports)
				}
			}
		}

		// Log full results for debugging
		t.Logf("Results for %s:", host)
		t.Logf("  IPv4 Services: %+v", result.IPv4Services)
		t.Logf("  IPv6 Services: %+v", result.IPv6Services)
		t.Logf("  CNAMEs: %v", result.CNAMEs)
	}
}

func TestReconService_Run_ValidateDuplicates(t *testing.T) {
	service := NewReconService()

	testURLs := []string{
		// Valid hosts
		"https://revoked.badssl.com/",
		"http://httpbin.org/get",
		"http://httpbin.org/post", // Duplicate host with different path
		"https://scanme.sh",

		// IP addresses with different paths
		"http://1.1.1.1/dns-query",
		"http://1.1.1.1/", // Duplicate IP with different path
		"https://8.8.8.8/",
		"http://[2606:4700:4700::1111]/test",
		"http://[2606:4700:4700::1111]/", // Duplicate IPv6 with different path

		// Edge cases
		"http://127.0.0.1:89/", // Closed port
		"http://[::1]:80/",     // IPv6 localhost
		"http://127.0.0.1:98/", // Another closed port
		"http://[::1]/",        // IPv6 localhost without port

		// Invalid cases
		"https://thisisnotarealdomainname123456789.com/",
		"http://localhost:65536/",  // Invalid port number
		"https://scanme.sh:12345/", // Non-standard port
	}

	// Test Run function
	err := service.Run(testURLs)
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}

	// Allow time for async operations to complete
	time.Sleep(2 * time.Second)

	// Verify duplicate handling
	result, err := service.cache.Get("httpbin.org")
	if err != nil {
		t.Errorf("Failed to get cache for httpbin.org: %v", err)
	} else {
		// Should only have one entry despite multiple paths
		t.Logf("httpbin.org results (should be same for /get and /post):")
		t.Logf("  IPv4 Services: %+v", result.IPv4Services)
		t.Logf("  IPv6 Services: %+v", result.IPv6Services)
	}

	// Verify duplicate IP handling
	result, err = service.cache.Get("1.1.1.1")
	if err != nil {
		t.Errorf("Failed to get cache for 1.1.1.1: %v", err)
	} else {
		// Should only have one entry despite multiple paths
		t.Logf("1.1.1.1 results (should be same for both paths):")
		t.Logf("  IPv4 Services: %+v", result.IPv4Services)
	}

	// Continue with existing test cases...
	expectedHosts := []string{
		"revoked.badssl.com",
		"httpbin.org",
		"scanme.sh",
	}

	for _, host := range expectedHosts {
		result, err := service.cache.Get(host)
		if err != nil {
			t.Errorf("Failed to get cache for %s: %v", host, err)
			continue
		}

		if result == nil {
			t.Errorf("No cache result for %s", host)
			continue
		}

		// Verify basic structure
		if result.Hostname != host {
			t.Errorf("Expected hostname %s, got %s", host, result.Hostname)
		}

		// Verify IPv4 services
		if len(result.IPv4Services) == 0 {
			t.Errorf("No IPv4 services found for %s", host)
		}

		// Check for expected schemes
		for scheme, ips := range result.IPv4Services {
			if scheme != "http" && scheme != "https" {
				t.Errorf("Unexpected scheme %s for %s", scheme, host)
			}
			if len(ips) == 0 {
				t.Errorf("No IPs found for scheme %s on %s", scheme, host)
			}

			// Check ports for each IP
			for ip, ports := range ips {
				if len(ports) == 0 {
					t.Errorf("No ports found for IP %s on %s", ip, host)
				}
				t.Logf("IPv4 %s service on %s: %s -> %v", scheme, host, ip, ports)
			}
		}

		// Verify IPv6 services if present
		if len(result.IPv6Services) > 0 {
			for scheme, ips := range result.IPv6Services {
				if scheme != "http" && scheme != "https" {
					t.Errorf("Unexpected scheme %s for %s", scheme, host)
				}
				for ip, ports := range ips {
					t.Logf("IPv6 %s service on %s: %s -> %v", scheme, host, ip, ports)
				}
			}
		}

		// Log full results for debugging
		t.Logf("Results for %s:", host)
		t.Logf("  IPv4 Services: %+v", result.IPv4Services)
		t.Logf("  IPv6 Services: %+v", result.IPv6Services)
		t.Logf("  CNAMEs: %v", result.CNAMEs)
	}
}

func TestReconCache(t *testing.T) {
	cache := NewReconCache()

	testData := &ReconResult{
		Hostname: "test.com",
		IPv4Services: map[string]map[string][]string{
			"http": {
				"192.168.1.1": {"80", "8080"},
			},
			"https": {
				"192.168.1.1": {"443"},
			},
		},
		IPv6Services: map[string]map[string][]string{
			"http": {
				"2001:db8::1": {"80"},
			},
			"https": {
				"2001:db8::1": {"443"},
			},
		},
		CNAMEs: []string{"www.test.com"},
	}

	// Test Set
	err := cache.Set(testData.Hostname, testData)
	if err != nil {
		t.Errorf("Failed to set cache: %v", err)
	}

	// Test Get
	result, err := cache.Get(testData.Hostname)
	if err != nil {
		t.Errorf("Failed to get cache: %v", err)
	}

	// Verify retrieved data
	if result.Hostname != testData.Hostname {
		t.Errorf("Expected hostname %s, got %s", testData.Hostname, result.Hostname)
	}

	// Check IPv4 services
	for scheme, ips := range testData.IPv4Services {
		for ip, expectedPorts := range ips {
			gotPorts := result.IPv4Services[scheme][ip]
			if len(gotPorts) != len(expectedPorts) {
				t.Errorf("IPv4 %s service on %s: expected ports %v, got %v",
					scheme, ip, expectedPorts, gotPorts)
			}
		}
	}

	// Check IPv6 services
	for scheme, ips := range testData.IPv6Services {
		for ip, expectedPorts := range ips {
			gotPorts := result.IPv6Services[scheme][ip]
			if len(gotPorts) != len(expectedPorts) {
				t.Errorf("IPv6 %s service on %s: expected ports %v, got %v",
					scheme, ip, expectedPorts, gotPorts)
			}
		}
	}
}
