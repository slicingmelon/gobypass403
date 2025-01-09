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

	"github.com/jedib0t/go-pretty/v6/text"
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
	timeoutFlag := flag.Int("timeout", 200, "Timeout to close connection (ms)")
	dumpFlag := flag.String("dump", "", "Dump incoming request to a file")
	portFlag := flag.String("port", "8888", "Listening port")
	tlsFlag := flag.Bool("tls", false, "Use TLS encryption")
	verboseFlag := flag.Bool("v", false, "Display request with special characters")
	helpFlag := flag.Bool("h", false, "Show help")

	// helper
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: http-echo-server [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Echo server accepting malformed HTTP requests\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Dump request to file:     http-echo-server -d request.txt\n")
		fmt.Fprintf(os.Stderr, "  Run with TLS:            http-echo-server --tls\n")
		fmt.Fprintf(os.Stderr, "  Show special characters: http-echo-server -v\n")
	}

	flag.Parse()

	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	verbose = *verboseFlag

	// Setup listener
	port := fmt.Sprintf(":%s", *portFlag)
	var ln net.Listener
	var err error

	if *tlsFlag {
		tlsConfig, err := generateTLSConfig()
		if err != nil {
			log.Fatalf("Failed to generate TLS config: %v", err)
		}
		ln, err = tls.Listen("tcp", port, tlsConfig)
	} else {
		ln, err = net.Listen("tcp", port)
	}

	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer ln.Close()

	log.Printf("Server listening on %s (TLS: %v)", port, *tlsFlag)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		conn.SetDeadline(time.Now().Add(time.Duration(*timeoutFlag) * time.Millisecond))
		go handleConnection(conn, *dumpFlag, *timeoutFlag)
	}
}

func handleConnection(conn net.Conn, dump string, timeout int) {
	defer conn.Close()

	var mu sync.Mutex
	var request strings.Builder

	// Send HTTP 200 OK response immediately
	if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}

	// Create buffered reader
	reader := bufio.NewReader(conn)

	// Channel to signal completion
	done := make(chan bool)
	defer close(done)

	// Handle incomplete requests
	go func() {
		select {
		case <-done:
			return
		case <-time.After(time.Duration(timeout) * time.Millisecond):
			mu.Lock()
			if reader.Buffered() > 0 {
				if data, err := reader.Peek(reader.Buffered()); err == nil {
					request.Write(data)
					printRequest(string(data), verbose)
				}
			}
			mu.Unlock()
			conn.Close()
		}
	}()

	// Read request line by line
	var currentRequest strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF &&
				!strings.Contains(err.Error(), "timeout") &&
				!strings.Contains(err.Error(), "closed network connection") {
				log.Printf("Read error: %v", err)
			}
			break
		}

		mu.Lock()
		currentRequest.WriteString(line)

		// If we have a complete request (empty line), print it
		if line == "\r\n" || line == "\n" {
			requestStr := currentRequest.String()
			printRequest(requestStr, verbose)
			request.WriteString(requestStr)
			currentRequest.Reset()

			// Echo back the complete request
			if _, err := conn.Write([]byte(requestStr)); err != nil {
				mu.Unlock()
				log.Printf("Write error: %v", err)
				break
			}
		}
		mu.Unlock()
	}

	// Dump final request if needed
	if dump != "" {
		mu.Lock()
		finalRequest := request.String()
		mu.Unlock()

		if err := os.WriteFile(dump, []byte(finalRequest), 0644); err != nil {
			log.Printf("Failed to dump request: %v", err)
		} else {
			log.Printf("\nRequest dumped to: %s\n", dump)
		}
	}
}

// Helper function to print requests
func printRequest(req string, verbose bool) {
	if verbose {
		// Replace special characters with colored versions
		req = strings.ReplaceAll(req, "\r", text.Colors{text.FgGreen}.Sprint("\\r"))
		req = strings.ReplaceAll(req, "\n", text.Colors{text.FgGreen}.Sprint("\\n\n"))
		fmt.Print(req)
	} else {
		fmt.Print(req)
	}
}
