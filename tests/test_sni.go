package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	host := "no-sni.badssl.com:443"
	// Intentionally leave ServerName blank to simulate "no SNI"
	conf := &tls.Config{
		InsecureSkipVerify: true, // you just want the raw cert
	}

	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		fmt.Fprintln(os.Stderr, "no certs presented")
		os.Exit(1)
	}

	cert := state.PeerCertificates[0]
	cn := cert.Subject.CommonName
	fmt.Println("Presented cert CN:", cn)

	// Now check if CN matches your intended hostname
	// (strip port, etc.)
	if cn != "no-sni.badssl.com" {
		fmt.Println("→ SNI missing or incorrect (got fallback cert)")
	} else {
		fmt.Println("→ Correct cert served")
	}
}
