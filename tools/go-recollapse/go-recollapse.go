package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type Recollapse struct {
	input     string
	file      string
	size      int
	encoding  int
	byteRange [2]int // [min, max] for byte fuzzing
	positions []int
	output    map[string]struct{}
	alphanum  bool
	maxNorm   int
}

const (
	ModeStart = 1
	ModeSep   = 2
	ModeNorm  = 3
	ModeTerm  = 4

	EncodingURL     = 1
	EncodingUnicode = 2
	EncodingRaw     = 3
)

func NewRecollapse() *Recollapse {
	return &Recollapse{
		output:    make(map[string]struct{}),
		byteRange: [2]int{0, 0xff}, // Default range
		size:      1,               // Default size
		encoding:  EncodingURL,     // Default encoding
		maxNorm:   3,               // Default max normalizations
	}
}

// generateFuzzingBytes generates all possible byte combinations in range
func (r *Recollapse) generateFuzzingBytes(position int) {
	// Generate all bytes in range
	for b := r.byteRange[0]; b <= r.byteRange[1]; b++ {
		// Skip alphanumeric if not requested
		if !r.alphanum && isAlphaNum(byte(b)) {
			continue
		}

		var result strings.Builder
		prefix := r.input[:position]
		suffix := r.input[position:]

		// Encode based on encoding type
		switch r.encoding {
		case EncodingURL:
			result.WriteString(prefix)
			result.WriteString(fmt.Sprintf("%%%02x", b))
			result.WriteString(suffix)
		case EncodingUnicode:
			result.WriteString(prefix)
			result.WriteString(fmt.Sprintf("\\u%04x", b))
			result.WriteString(suffix)
		case EncodingRaw:
			if b >= 10 && b < 13 || b == 27 {
				continue
			}
			result.WriteString(prefix)
			result.WriteRune(rune(b))
			result.WriteString(suffix)
		}

		r.output[result.String()] = struct{}{}
	}
}

func (r *Recollapse) generateNormalizationPayloads() {
	// Use all normalization forms
	forms := []norm.Form{
		norm.NFC,
		norm.NFD,
		norm.NFKC,
		norm.NFKD,
	}

	for _, form := range forms {
		for i := 0; i < len(r.input); i++ {
			c := rune(r.input[i])

			// Get normalized versions
			normalized := form.String(string(c))
			if normalized != string(c) {
				prefix := r.input[:i]
				suffix := r.input[i+1:]
				r.output[prefix+normalized+suffix] = struct{}{}
			}
		}
	}
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

func main() {
	r := NewRecollapse()

	// Parse flags
	flag.StringVar(&r.file, "f", "", "Input file")
	flag.IntVar(&r.size, "s", 1, "Payload size")
	flag.IntVar(&r.encoding, "e", EncodingURL, "Encoding (1:URL, 2:Unicode, 3:Raw)")
	flag.BoolVar(&r.alphanum, "an", false, "Include alphanumeric bytes")
	flag.IntVar(&r.maxNorm, "mn", 3, "Maximum normalizations")
	flag.Parse()

	// Handle input priority
	if args := flag.Args(); len(args) > 0 {
		r.input = args[0]
	} else if r.file != "" {
		data, err := os.ReadFile(r.file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		r.input = strings.TrimSpace(string(data))
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			r.input = strings.TrimSpace(scanner.Text())
		}
	}

	// Validate input
	if r.input == "" {
		fmt.Fprintf(os.Stderr, "No input provided\n")
		os.Exit(1)
	}

	// Generate payloads
	// Start position fuzzing
	r.generateFuzzingBytes(0)

	// Separator position fuzzing
	for i := 0; i < len(r.input); i++ {
		if strings.ContainsRune("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", rune(r.input[i])) {
			r.generateFuzzingBytes(i)
			r.generateFuzzingBytes(i + 1)
		}
	}

	// Normalization fuzzing
	r.generateNormalizationPayloads()

	// Termination position fuzzing
	r.generateFuzzingBytes(len(r.input))

	// Output results
	for result := range r.output {
		fmt.Println(result)
	}
}
