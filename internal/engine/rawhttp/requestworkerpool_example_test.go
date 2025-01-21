package rawhttp

import (
	"fmt"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
)

func ExampleRequestPool2_new() {
	clientOpts := &HttpClientOptions{
		Timeout:         30 * time.Second,
		MaxConnsPerHost: 100,
		MaxRetries:      3,
	}

	scanOpts := &ScannerCliOpts{
		MaxWorkers:              50,
		ResponseBodyPreviewSize: 1024,
		MatchStatusCodes:        []int{200, 301, 302},
	}

	errorHandler := GB403ErrorHandler.NewErrorHandler(32)
	pool := NewRequestPool2(clientOpts, scanOpts, errorHandler)
	defer pool.Close()

	fmt.Printf("Pool initialized with %d max workers\n", scanOpts.MaxWorkers)
	// Output:
	// Pool initialized with 50 max workers
}

func ExampleRequestPool2_ProcessRequests() {
	// Create options similar to bypass.go's NewWorkerContext
	clientOpts := DefaultHTTPClientOptions()

	scanOpts := &ScannerCliOpts{
		MaxWorkers:              50,
		ResponseBodyPreviewSize: 1024,
		MatchStatusCodes:        []int{200, 301, 302},
	}

	errorHandler := GB403ErrorHandler.NewErrorHandler(32)

	// Create the new pool
	pool := NewRequestPool2(clientOpts, scanOpts, errorHandler)
	defer pool.Close() // Ensure cleanup

	// Create some test jobs
	jobs := []payload.PayloadJob{
		{
			FullURL:      "https://github.com/test1",
			Method:       "GET",
			BypassModule: "test-module",
			Host:         "github.com",
		},
		{
			FullURL:      "https://github.com/test2",
			Method:       "GET",
			BypassModule: "test-module",
			Host:         "github.com",
		},
	}

	// Process requests
	responses := pool.ProcessRequests(jobs)

	// Handle responses
	for response := range responses {
		if response != nil {
			fmt.Printf("Got response: %d for %s\n", response.StatusCode, response.URL)
		}
	}
}
