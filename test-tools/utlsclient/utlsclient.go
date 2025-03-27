package main

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/valyala/fasthttp"
)

var badsslDomains = []string{
	"https://expired.badssl.com",
	"https://wrong.host.badssl.com",
	"https://self-signed.badssl.com",
	"https://untrusted-root.badssl.com",
	"https://revoked.badssl.com",
	"https://pinning-test.badssl.com",
	"https://no-common-name.badssl.com",
	"https://no-subject.badssl.com",
	"https://incomplete-chain.badssl.com",
	"https://sha256.badssl.com",
	"https://sha384.badssl.com",
	"https://sha512.badssl.com",
	"https://1000-sans.badssl.com",
	"https://10000-sans.badssl.com",
	"https://ecc256.badssl.com",
	"https://ecc384.badssl.com",
	"https://rsa2048.badssl.com",
	"https://rsa4096.badssl.com",
	"https://rsa8192.badssl.com",
	"https://extended-validation.badssl.com",
	"https://client.badssl.com",
	"https://client-cert-missing.badssl.com",
	"https://mixed-script.badssl.com",
	"https://very.badssl.com",
	"https://mixed.badssl.com",
	"https://mixed-favicon.badssl.com",
	"https://mixed-form.badssl.com",
	"https://http.badssl.com",
	"https://http-textarea.badssl.com",
	"https://http-password.badssl.com",
	"https://http-login.badssl.com",
	"https://http-dynamic-login.badssl.com",
	"https://http-credit-card.badssl.com",
	"https://cbc.badssl.com",
	"https://rc4-md5.badssl.com",
	"https://rc4.badssl.com",
	"https://3des.badssl.com",
	"https://null.badssl.com",
	"https://mozilla-old.badssl.com",
	"https://mozilla-intermediate.badssl.com",
	"https://mozilla-modern.badssl.com",
	"https://dh480.badssl.com",
	"https://dh512.badssl.com",
	"https://dh1024.badssl.com",
	"https://dh2048.badssl.com",
	"https://dh-small-subgroup.badssl.com",
	"https://dh-composite.badssl.com",
	"https://static-rsa.badssl.com",
	"https://tls-v1-0.badssl.com:1010",
	"https://tls-v1-1.badssl.com:1011",
	"https://tls-v1-2.badssl.com:1012",
	"https://no-sct.badssl.com",
	"https://hsts.badssl.com",
	"https://upgrade.badssl.com",
	"https://preloaded-hsts.badssl.com",
	"https://subdomain.preloaded-hsts.badssl.com",
	"https://https-everywhere.badssl.com",
	"https://spoofed-favicon.badssl.com",
	"https://lock-title.badssl.com",
	"https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com",
	"https://longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com",
	"https://superfish.badssl.com",
	"https://edellroot.badssl.com",
	"https://dsdtestprovider.badssl.com",
	"https://preact-cli.badssl.com",
	"https://webpack-dev-server.badssl.com",
	"https://captive-portal.badssl.com",
	"https://mitm-software.badssl.com",
	"https://sha1-2016.badssl.com",
	"https://sha1-2017.badssl.com",
	"https://sha1-intermediate.badssl.com",
	"https://invalid-expected-sct.badssl.com",
}

func init() {
	// Enable weak ciphers for testing
	tls.EnableWeakCiphers()
}

var (
	helloIds = []tls.ClientHelloID{
		tls.HelloRandomized,
		tls.HelloRandomizedALPN,
		tls.HelloRandomizedNoALPN,
		tls.HelloFirefox_Auto,
		tls.HelloFirefox_102,
		tls.HelloFirefox_105,
		tls.HelloChrome_Auto,
		tls.HelloChrome_100,
		tls.HelloChrome_102,
		tls.HelloChrome_106_Shuffle,
		tls.HelloChrome_100_PSK,
		tls.HelloChrome_112_PSK_Shuf,
		tls.HelloChrome_114_Padding_PSK_Shuf,
		tls.HelloChrome_115_PQ,
		tls.HelloChrome_115_PQ_PSK,
	}
	uHttpClient = &fasthttp.Client{}
)

func main() {
	useFastHTTP := flag.Bool("fasthttpclient", false, "Use fasthttp client")
	useNetHTTP := flag.Bool("nethttpclient", false, "Use net/http client")
	flag.Parse()

	if *useFastHTTP && *useNetHTTP {
		fmt.Println("Error: Only one client type can be specified")
		return
	}

	if !*useFastHTTP && !*useNetHTTP {
		fmt.Println("Error: Please specify either -fasthttpclient or -nethttpclient")
		return
	}

	if *useFastHTTP {
		RunWithFastHTTPClient(badsslDomains)
	} else {
		//RunWithNetHTTPClient(badsslDomains)
		fmt.Println("Not yet implemented")
	}
}

func RunWithFastHTTPClient(domains []string) {
	// Create fasthttp client with custom Dial
	uHttpClient := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			host := strings.Split(addr, ":")[0]

			// Establish a TCP connection
			tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("TCP connection failed to %s: %v", addr, err)
			}

			// Wrap with uTLS and use HelloRandomized for fingerprinting resistance
			client := tls.UClient(tcpConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}, tls.HelloRandomized)
			client.SetSNI(host)
			client.SetDeadline(time.Now().Add(10 * time.Second)) // Set handshake timeout

			// Perform the TLS handshake
			if err := client.Handshake(); err != nil {
				return nil, fmt.Errorf("TLS handshake failed for %s: %v", addr, err)
			}

			return client, nil
		},
		MaxConnsPerHost:     5,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        15 * time.Second,
		MaxIdleConnDuration: 10 * time.Second,
	}

	// Test each domain
	for _, domain := range domains {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(domain)
		req.Header.SetMethod(fasthttp.MethodGet)

		fmt.Printf("Sending request to %s\n", domain)
		if err := uHttpClient.DoTimeout(req, resp, 15*time.Second); err != nil {
			fmt.Printf("Failed to send request to %s: %v\n", domain, err)
			continue
		}

		// Print response headers
		fmt.Printf("\nResponse Headers for %s:\n", domain)
		resp.Header.VisitAll(func(key, value []byte) {
			fmt.Printf("%s: %s\n", key, value)
		})

		fmt.Println(strings.Repeat("-", 50))
		time.Sleep(500 * time.Millisecond) // Avoid overwhelming the server
	}
}
