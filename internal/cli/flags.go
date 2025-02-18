package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type multiFlag struct {
	name   string
	usage  string
	value  interface{}
	defVal interface{}
}

var flags []multiFlag

func parseFlags() (*CliOptions, error) {
	opts := &CliOptions{}

	flags := []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &opts.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &opts.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)", value: &opts.SubstituteHostsFile},
		{name: "m,module", usage: "Bypass module (all, mid_paths, end_paths, case_substitution, char_encode,unicode_path_normalization, http_headers_scheme, http_headers_ip, http_headers_port, http_headers_url, http_host)", value: &opts.Module, defVal: "all"},
		{name: "o,outdir", usage: "Output directory", value: &opts.OutDir},
		{name: "t,threads", usage: "Number of concurrent threads", value: &opts.Threads, defVal: 15},
		{name: "T,timeout", usage: "Total timeout (in milliseconds)", value: &opts.Timeout, defVal: 20000},
		{name: "delay", usage: "Delay between requests (in milliseconds)", value: &opts.Delay, defVal: 0},
		{name: "max-retries", usage: "Maximum number of retries for failed requests", value: &opts.MaxRetries, defVal: 2},
		{name: "retry-delay", usage: "Delay between retries (in milliseconds)", value: &opts.RetryDelay, defVal: 500},
		{name: "max-cfr,max-consecutive-fails", usage: "Maximum number of consecutive failed requests before cancelling the current bypass module", value: &opts.MaxConsecutiveFailedReqs, defVal: 15},
		{name: "v,verbose", usage: "Verbose output", value: &opts.Verbose, defVal: false},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &opts.Debug, defVal: false},
		{name: "mc,match-status-code", usage: "Filter results by HTTP status codes (example: -mc 200, 301, 500, all). Default: All status codes", value: &opts.MatchStatusCodesStr},
		{name: "http2", usage: "Enable HTTP2 client", value: &opts.EnableHTTP2, defVal: false},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port) (Example: -x http://127.0.0.1:8080)", value: &opts.Proxy},
		{name: "spoof-header", usage: "Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)", value: &opts.SpoofHeader},
		{name: "spoof-ip", usage: "Add more spoof IPs (example: 10.10.20.20,172.16.30.10)", value: &opts.SpoofIP},
		{name: "fr,follow-redirects", usage: "Follow HTTP redirects", value: &opts.FollowRedirects},
		{name: "rbps,response-body-preview-size", usage: "Maximum number of bytes to retrieve from response body", value: &opts.ResponseBodyPreviewSize, defVal: 1024},
		{name: "disable-response-body-streaming", usage: "Disables streaming of response body (default: False)", value: &opts.DisableStreamResponseBody, defVal: false},
		{name: "update-payloads", usage: "Update payload files to latest version", value: &opts.UpdatePayloads, defVal: false},
		{name: "dpg,disable-progress-bar", usage: "Disable progress bar", value: &opts.DisableProgressBar, defVal: false},
		{name: "resend,resend-request", usage: "Resend the exact request using the debug token (example: -resend xyzdebugtoken)", value: &opts.ResendRequest},
		{name: "resend-count,resend-request-count", usage: "Number of times to resend the debugged request (Default: 1)", value: &opts.ResendCount, defVal: 1},
		{name: "profile", usage: "Enable pprof profiler", value: &opts.Profile, defVal: false},
	}

	// Set up custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Go-Bypass-403\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		for _, f := range flags {
			names := strings.Split(f.name, ",")
			if len(names) > 1 {
				fmt.Fprintf(os.Stderr, "  -%s, -%s\n", names[0], names[1])
			} else {
				fmt.Fprintf(os.Stderr, "  -%s\n", names[0])
			}

			if f.defVal != nil {
				fmt.Fprintf(os.Stderr, "        %s (Default: %v)\n", f.usage, f.defVal)
			} else {
				fmt.Fprintf(os.Stderr, "        %s\n", f.usage)
			}
		}
	}

	// Register all flags
	for _, f := range flags {
		for _, name := range strings.Split(f.name, ",") {
			name = strings.TrimSpace(name)
			switch v := f.value.(type) {
			case *string:
				if def, ok := f.defVal.(string); ok {
					flag.StringVar(v, name, def, f.usage)
				} else {
					flag.StringVar(v, name, "", f.usage)
				}
			case *int:
				if def, ok := f.defVal.(int); ok {
					flag.IntVar(v, name, def, f.usage)
				} else {
					flag.IntVar(v, name, 0, f.usage)
				}
			case *bool:
				if def, ok := f.defVal.(bool); ok {
					flag.BoolVar(v, name, def, f.usage)
				} else {
					flag.BoolVar(v, name, false, f.usage)
				}
			}
		}
	}

	// Parse flags
	flag.Parse()

	// Set defaults and validate
	opts.setDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	return opts, nil
}
