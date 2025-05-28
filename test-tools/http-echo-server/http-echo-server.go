package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// To trigger timeout errors when testing: ./http-echo-server.exe -port 80 -tlsport 443 -v -template timeout -timeout 5000
// To trigger server closed connection before returning first byte: ./http-echo-server.exe -port 80 -tlsport 443 -v -template timeout -timeout 200

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorWhite  = "\033[37m"
)

var verbose bool

func generateTLSConfig() (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"HTTP Echo Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func main() {
	log.SetFlags(log.Lshortfile)

	// cli args
	dumpFlag := flag.String("dump", "", "Dump incoming request to a file")
	portFlag := flag.String("port", "", "HTTP listening port")
	tlsPortFlag := flag.String("tlsport", "", "HTTPS/TLS listening port")
	verboseFlag := flag.Bool("v", false, "Display request with special characters")
	templateFlag := flag.String("template", "echo", "Response template (echo, timeout)")
	timeoutFlag := flag.Int("timeout", 200, "Timeout to close connection (ms)")
	helpFlag := flag.Bool("h", false, "Show help")

	// helper
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: http-echo-server [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Echo server accepting malformed HTTP requests\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  HTTP only:              http-echo-server -port 8888\n")
		fmt.Fprintf(os.Stderr, "  HTTPS only:             http-echo-server -tlsport 8443\n")
		fmt.Fprintf(os.Stderr, "  Both HTTP and HTTPS:    http-echo-server -port 8888 -tlsport 8443\n")
		fmt.Fprintf(os.Stderr, "  Dump request to file:   http-echo-server -port 8888 -d request.txt\n")
		fmt.Fprintf(os.Stderr, "  Show special chars:     http-echo-server -port 8888 -v\n")
		fmt.Fprintf(os.Stderr, "  Timeout template:       http-echo-server -port 8888 -template timeout\n")
		fmt.Fprintf(os.Stderr, "  Timeout template:       http-echo-server -port 8888 -template timeout -timeout 5000\n")
	}

	flag.Parse()

	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if *templateFlag != "echo" && *templateFlag != "timeout" {
		log.Fatal("Template must be either 'echo' or 'timeout'")
	}

	if *portFlag == "" && *tlsPortFlag == "" {
		log.Fatal("At least one of -port or -tlsport must be specified")
	}

	verbose = *verboseFlag

	var wg sync.WaitGroup

	if *portFlag != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpPort := fmt.Sprintf(":%s", *portFlag)
			ln, err := net.Listen("tcp", httpPort)
			if err != nil {
				log.Fatalf("Failed to start HTTP listener: %v", err)
			}
			defer ln.Close()
			log.Printf("HTTP Server listening on %s", httpPort)

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("Failed to accept HTTP connection: %v", err)
					continue
				}
				conn.SetDeadline(time.Now().Add(time.Duration(*timeoutFlag) * time.Millisecond))
				go handleConnection(conn, *dumpFlag, *timeoutFlag, *templateFlag)
			}
		}()
	}

	// Start HTTPS server if tlsport specified
	if *tlsPortFlag != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tlsPort := fmt.Sprintf(":%s", *tlsPortFlag)

			tlsConfig, err := generateTLSConfig()
			if err != nil {
				log.Fatalf("Failed to generate TLS config: %v", err)
			}

			ln, err := tls.Listen("tcp", tlsPort, tlsConfig)
			if err != nil {
				log.Fatalf("Failed to start HTTPS listener: %v", err)
			}
			defer ln.Close()
			log.Printf("HTTPS Server listening on %s", tlsPort)

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("Failed to accept HTTPS connection: %v", err)
					continue
				}
				conn.SetDeadline(time.Now().Add(time.Duration(*timeoutFlag) * time.Millisecond))
				go handleConnection(conn, *dumpFlag, *timeoutFlag, *templateFlag)
			}
		}()
	}

	wg.Wait()
}

func handleConnection(conn net.Conn, dump string, timeout int, template string) {
	// Set a deadline for the entire connection
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
	}
	defer conn.Close()

	// Determine if connection is TLS
	_, isTLS := conn.(*tls.Conn)

	// Read the request first
	reader := bufio.NewReader(conn)
	var request strings.Builder

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF &&
				!strings.Contains(err.Error(), "timeout") &&
				!strings.Contains(err.Error(), "closed network connection") {
				log.Printf("Read error: %v", err)
			}
			return
		}
		request.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Read body if Content-Length is present
	requestStr := request.String()
	contentLength := extractContentLength(requestStr)
	if contentLength > 0 {
		bodyBytes := make([]byte, contentLength)
		_, err := io.ReadFull(reader, bodyBytes)
		if err != nil {
			log.Printf("Error reading body: %v", err)
		} else {
			request.WriteString(string(bodyBytes))
			requestStr = request.String()
		}
	}

	// Print the request with proper formatting
	if requestStr != "" {
		printRequest(requestStr, verbose, isTLS)
	}

	// Handle different templates
	switch template {
	case "timeout":
		fmt.Printf("Sleeping for 1 seconds...\n")
		time.Sleep(1 * time.Second)
		fmt.Printf("Sleep done, sending response\n")

		response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
			len(requestStr), requestStr)

		conn.Write([]byte(response))

	case "echo":
		// Immediately send complete response
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
			len(requestStr), requestStr)

		conn.Write([]byte(response))
	}

	// Handle request dumping if enabled
	if dump != "" && requestStr != "" {
		if err := os.WriteFile(dump, []byte(requestStr), 0644); err != nil {
			log.Printf("Failed to dump request: %v", err)
		} else {
			log.Printf("\nRequest dumped to: %s\n", dump)
		}
	}
}

// extractContentLength parses Content-Length header from request string
func extractContentLength(request string) int {
	lines := strings.Split(request, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				length := strings.TrimSpace(parts[1])
				if val, err := fmt.Sscanf(length, "%d", &length); err == nil && val == 1 {
					var contentLength int
					fmt.Sscanf(length, "%d", &contentLength)
					return contentLength
				}
			}
		}
	}
	return 0
}

// Helper function to print requests

func printRequest(req string, verbose bool, isTLS bool) {
	if verbose {
		// Handle CRLF sequences specially - they should be colored together
		req = strings.ReplaceAll(req, "\r\n", colorGreen+"\\r\\n"+colorReset+"\n")

		// Handle remaining special characters
		specialChars := map[string]string{
			"\r": colorGreen + "\\r" + colorReset,
			"\n": colorGreen + "\\n" + colorReset + "\n", // Keep the extra newline for readability
			"\t": colorGreen + "\\t" + colorReset,
			"\v": colorGreen + "\\v" + colorReset, // Vertical tab
			"\f": colorGreen + "\\f" + colorReset, // Form feed
			"\b": colorGreen + "\\b" + colorReset, // Backspace
			"\a": colorGreen + "\\a" + colorReset, // Alert/Bell
		}

		for char, replacement := range specialChars {
			req = strings.ReplaceAll(req, char, replacement)
		}
	}

	// Color the terminal output based on connection type
	if isTLS {
		fmt.Print(colorYellow + req + colorReset)
	} else {
		fmt.Print(colorWhite + req + colorReset)
	}
	fmt.Println() // Add extra newline for separation between requests
}
