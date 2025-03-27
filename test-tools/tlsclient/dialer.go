package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

// SOOON -> https://github.com/refraction-networking/utls#roller

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

	caCert, key, err := GenerateCertForHost("localhost")
	if err != nil {
		panic(err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		panic("not ok")
	}

	cert, err := tls.X509KeyPair(caCert, key)
	if err != nil {
		panic(err)
	}

	go server(caCertPool, cert)
	time.Sleep(time.Second)

	if *useFastHTTP {
		fasthttpClient(badsslDomains)
	} else {
		httpClient(badsslDomains)
	}
}

func fasthttpClient(domains []string) {
	client := &fasthttp.Client{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
			// Enable all cipher suites
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			// Enable all curves
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.X25519,
			},
		},
	}

	var totalRequests int64
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			for i := 0; i < 5; i++ { // Test each domain 5 times
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()

				req.Header.SetMethod(fasthttp.MethodGet)
				req.SetRequestURI(d)

				if err := client.DoTimeout(req, resp, 10*time.Second); err != nil {
					fmt.Printf("Error testing %s: %v\n", d, err)
				}

				atomic.AddInt64(&totalRequests, 1)

				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
			}
		}(domain)
	}

	// Print stats
	go func() {
		for {
			time.Sleep(time.Second)
			r := atomic.LoadInt64(&totalRequests)
			fmt.Printf("%d requests completed, %d goroutines\n", r, runtime.NumGoroutine())
		}
	}()

	wg.Wait()
}

func httpClient(domains []string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConns:        2000,
			MaxIdleConnsPerHost: 200,
			MaxConnsPerHost:     2000,
			IdleConnTimeout:     20 * time.Second,
			//WriteBufferSize:     1024,
			//ReadBufferSize:      1024,
			TLSClientConfig: &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(64),
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			},
		},
	}

	var totalRequests int64
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			for i := 0; i < 5; i++ { // Test each domain 5 times
				resp, err := client.Get(d)
				if err != nil {
					fmt.Printf("Error testing %s: %v\n", d, err)
					continue
				}

				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					fmt.Printf("Error reading response from %s: %v\n", d, err)
				}

				atomic.AddInt64(&totalRequests, 1)
			}
		}(domain)
	}

	// Print stats
	go func() {
		for {
			time.Sleep(time.Second)
			r := atomic.LoadInt64(&totalRequests)
			fmt.Printf("%d requests completed, %d goroutines\n", r, runtime.NumGoroutine())
		}
	}()

	wg.Wait()
}

// Helper function to print stats
func printStats(requests *int64) {
	for {
		time.Sleep(time.Second)
		r := atomic.SwapInt64(requests, 0)
		fmt.Printf("%d req/s, %d goroutines\n", r, runtime.NumGoroutine())
	}
}

// GenerateCert generates certificate and private key based on the given host.
func GenerateCertForHost(host string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GBFO3"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader, cert, cert, &priv.PublicKey, priv,
	)

	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	b := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	)

	return b, p, err
}

/*
$ .\tlsclient.exe -nethttpclient
55711 req/s, 20 goroutines
53441 req/s, 20 goroutines
55418 req/s, 20 goroutines
53877 req/s, 20 goroutines
52206 req/s, 20 goroutines
52025 req/s, 20 goroutines
51541 req/s, 20 goroutines
38628 req/s, 20 goroutines
37985 req/s, 20 goroutines
37719 req/s, 20 goroutines
38392 req/s, 20 goroutines
38002 req/s, 20 goroutines
38059 req/s, 20 goroutines
38209 req/s, 20 goroutines
38527 req/s, 20 goroutines
37358 req/s, 20 goroutines
37637 req/s, 20 goroutines
35676 req/s, 20 goroutines
36752 req/s, 20 goroutines
37301 req/s, 20 goroutines
35430 req/s, 20 goroutines
24147 req/s, 20 goroutines
34153 req/s, 20 goroutines
37123 req/s, 20 goroutines
37195 req/s, 20 goroutines
38515 req/s, 20 goroutines
38495 req/s, 20 goroutines
37985 req/s, 20 goroutines
37997 req/s, 20 goroutines
37907 req/s, 20 goroutines
38205 req/s, 20 goroutines
37509 req/s, 20 goroutines
36606 req/s, 20 goroutines
38654 req/s, 20 goroutines
39271 req/s, 20 goroutines
37523 req/s, 20 goroutines
35759 req/s, 20 goroutines
33681 req/s, 20 goroutines
37002 req/s, 20 goroutines
37170 req/s, 20 goroutines
35989 req/s, 20 goroutines
36483 req/s, 20 goroutines
35492 req/s, 20 goroutines


╰─ $ .\tlsclient.exe -fasthttpclient
66653 req/s, 15 goroutines
63733 req/s, 15 goroutines
62564 req/s, 15 goroutines
65943 req/s, 15 goroutines
64126 req/s, 15 goroutines
65058 req/s, 15 goroutines
62474 req/s, 15 goroutines
48227 req/s, 15 goroutines
48717 req/s, 15 goroutines
44917 req/s, 15 goroutines
45021 req/s, 15 goroutines
45393 req/s, 15 goroutines
47791 req/s, 15 goroutines
46780 req/s, 15 goroutines
48088 req/s, 15 goroutines
46858 req/s, 15 goroutines
46519 req/s, 15 goroutines
46996 req/s, 15 goroutines
47594 req/s, 15 goroutines
47208 req/s, 15 goroutines
46523 req/s, 15 goroutines
48039 req/s, 15 goroutines
47513 req/s, 15 goroutines
44085 req/s, 15 goroutines
48088 req/s, 15 goroutines
46290 req/s, 15 goroutines
46884 req/s, 15 goroutines
47268 req/s, 15 goroutines
47472 req/s, 15 goroutines
46647 req/s, 15 goroutines
45914 req/s, 15 goroutines
46906 req/s, 15 goroutines
46701 req/s, 15 goroutines
47835 req/s, 15 goroutines
46920 req/s, 15 goroutines
48147 req/s, 15 goroutines
47209 req/s, 15 goroutines
47957 req/s, 15 goroutines
47985 req/s, 15 goroutines
45963 req/s, 15 goroutines
43792 req/s, 15 goroutines
45705 req/s, 15 goroutines
44978 req/s, 15 goroutines
44114 req/s, 15 goroutines
43656 req/s, 15 goroutines
44932 req/s, 15 goroutines
46420 req/s, 15 goroutines
44805 req/s, 15 goroutines
45026 req/s, 15 goroutines
46091 req/s, 15 goroutines
40264 req/s, 15 goroutines
45019 req/s, 15 goroutines
45794 req/s, 15 goroutines
*/

func server(caCertPool *x509.CertPool, cert tls.Certificate) {
	// Create the TLS Config with the CA pool and enable Client certificate validation
	cfg := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp4", "localhost:8443")
	if err != nil {
		panic(err)
	}

	lnTls := tls.NewListener(ln, cfg)

	server := &fasthttp.Server{
		IdleTimeout:        30 * time.Second,
		TCPKeepalive:       true,
		TCPKeepalivePeriod: 30 * time.Second,
		MaxConnsPerIP:      200,
		Handler: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(200)
			ctx.SetBody([]byte("hello"))
		},
	}

	if err := server.Serve(lnTls); err != nil {
		panic(err)
	}
}
