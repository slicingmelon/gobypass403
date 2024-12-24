package recon

import (
	"testing"
	"time"
)

func TestReconService_Run(t *testing.T) {
	service := NewReconService()

	testURLs := []string{
		"https://revoked.badssl.com/",
		"http://httpbin.org/get",
		"https://scanme.sh",
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

		// Verify ports
		if len(result.Ports) == 0 {
			t.Errorf("No ports found for %s", host)
		}

		// Verify IP addresses
		if len(result.IPv4) == 0 && len(result.IPv6) == 0 {
			t.Errorf("No IP addresses found for %s", host)
		}

		// Log results for debugging
		t.Logf("Results for %s:", host)
		t.Logf("  Ports: %v", result.Ports)
		t.Logf("  IPv4: %v", result.IPv4)
		t.Logf("  IPv6: %v", result.IPv6)
		t.Logf("  CNAMEs: %v", result.CNAMEs)
	}
}

func TestReconCache(t *testing.T) {
	cache := NewReconCache()

	testData := &ReconResult{
		Hostname: "test.com",
		Ports: map[string]string{
			"80":  "http",
			"443": "https",
		},
		IPv4:   []string{"1.2.3.4"},
		IPv6:   []string{"2001:db8::1"},
		CNAMEs: []string{"alias.test.com"},
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

	if len(result.Ports) != len(testData.Ports) {
		t.Errorf("Expected %d ports, got %d", len(testData.Ports), len(result.Ports))
	}

	if len(result.IPv4) != len(testData.IPv4) {
		t.Errorf("Expected %d IPv4 addresses, got %d", len(testData.IPv4), len(result.IPv4))
	}

	if len(result.IPv6) != len(testData.IPv6) {
		t.Errorf("Expected %d IPv6 addresses, got %d", len(testData.IPv6), len(result.IPv6))
	}
}
