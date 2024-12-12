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

func parseFlags() (*Options, error) {
	opts := &Options{}

	flags := []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &opts.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &opts.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)", value: &opts.SubstituteHostsFile},
		{name: "m,module", usage: "Bypass module (all, mid_paths, end_paths, case_substitution, char_encode, http_headers_scheme, http_headers_ip, http_headers_port, http_headers_url, http_host)", value: &opts.Module, defVal: "all"},
		{name: "o,outdir", usage: "Output directory", value: &opts.OutDir},
		{name: "t,threads", usage: "Number of concurrent threads", value: &opts.Threads, defVal: 15},
		{name: "T,timeout", usage: "Timeout in seconds", value: &opts.Timeout, defVal: 15},
		{name: "delay", usage: "Delay between requests in milliseconds", value: &opts.Delay, defVal: 150},
		{name: "v,verbose", usage: "Verbose output", value: &opts.Verbose},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &opts.Debug},
		{name: "trace", usage: "Trace HTTP requests", value: &opts.TraceRequests},
		{name: "mc,match-status-code", usage: "Only save results matching these HTTP status codes (example: -mc 200,301,500)", value: &opts.MatchStatusCodesStr},
		{name: "http2", usage: "Force attempt requests on HTTP2", value: &opts.ForceHTTP2},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port)", value: &opts.Proxy},
		{name: "spoof-header", usage: "Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)", value: &opts.SpoofHeader},
		{name: "spoof-ip", usage: "Add more spoof IPs (example: 10.10.20.20,172.16.30.10)", value: &opts.SpoofIP},
		{name: "fr,follow-redirects", usage: "Follow HTTP redirects", value: &opts.FollowRedirects},
		{name: "mrs,max-response-body-size", usage: "Maximum response body size in bytes", value: &opts.MaxResponseBodySize, defVal: 1024}, // 1024 bytes
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
