# Go-Bypass-403

A powerful WAF/403 bypass tool written in Go that specializes in preserving exact URL paths and structures during testing. This is the first Golang-based tool that properly handles URL bypasses by using a custom URL parser ([go-rawurlparser](https://github.com/slicingmelon/go-rawurlparser)) to maintain raw URL paths without any automatic encoding or normalization.

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

# Installation

```bash
git clone https://github.com/slicingmelon/go-bypass-403.git
go get
go build
```

# Usage

```
.\go-bypass-403.exe -h
Go-Bypass-403:
  -u, -url
        Target URL (example: https://cms.facebook.com/login)
  -l, -urls-file
        File containing list of target URLs (one per line)
  -shf, -substitute-hosts-file
        File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)
  -m, -mode
        Bypass mode (all, http_methods, headers, paths, etc)
  -o, -outdir
        Output directory
  -t, -threads
        Number of concurrent threads
  -T, -timeout
        Timeout in seconds
  -v, -verbose
        Verbose output
  -x, -proxy
        Proxy URL (format: http://proxy:port)
  -mc, -match-status-code
        Only save results matching these HTTP status codes (example: -mc 200,301,500). Default: 200
```

## Standard WAF 403/401 Bypass

Standard command(s):
```bash
go-bypass-403 -u "https://go-test-webapp.com/admin" -mc "200"
go-bypass-403 -u "https://go-test-webapp.com/admin" -mc "200,500" -t 10 -v 
```

Using a list of target URLs:
```bash
go-bypass-403 -l "targeturls.txt" 
```

## Find CDN Bypasses Using A List Of Hosts 

Sometimes you want to find bypasses in a long list of CDNs, and you know that the video path is always the same. Example when you want to bypass the hash check on a video or image.

// Redacted. Will update.

## Screenshots

Example Results 1
![Screenshot 1](images/1.jpg)


# Changelog

## 05 November 2024

- First official release

## Credits


This tool was inspired by and based on [laluka's bypass-url-parser](https://github.com/laluka/bypass-url-parser). All credit for the original concept and bypass techniques goes to him.

Special thanks to [laluka](https://github.com/laluka) for open-sourcing his work and his vast bypass techniques implemented in his tool.

