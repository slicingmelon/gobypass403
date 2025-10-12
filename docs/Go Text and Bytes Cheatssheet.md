# Go Text & Bytes Cheatsheet

A compact, practical reference for working with bytes, strings, and runes in Go, plus the right (and wrong) ways to convert between them.

## TL;DR

- `byte` = `uint8` (0–255). A `[]byte` is raw bytes; it doesn't "know" text.
- `string` = immutable sequence of bytes (by convention UTF-8).
- `rune` = `int32` Unicode code point (not "UTF-8 char").
- Rune operations are character-based, not byte-based.
  
```go
len("a")   == 1                 // 0x61
len("€")   == 3                 // E2 82 AC (UTF-8)
len("你")  == 3                 // UTF-8 length, not “characters”
utf8.RuneCountInString("€") == 1
```

**Casting isn't encoding/decoding.**

`byte(x)` / `rune(x)` only change numeric types. To go between runes and UTF-8 bytes, encode/decode.

## Types at a glance

| Type     | Meaning                              | Notes                                    |
|----------|--------------------------------------|------------------------------------------|
| `byte`   | alias of `uint8`                     | One raw byte (0-255)                     |
| `[]byte` | byte slice                           | Raw buffer; I/O, hashing, sockets        |
| `string` | sequence of bytes (UTF-8 by conv.)   | Immutable; may contain invalid UTF-8     |
| `rune`   | alias of `int32` (Unicode codepoint) | Logical "character"; not UTF-8 length    |
| `[]rune` | slice of runes                       | One element per code point               |


## Bytes vs Hex string (common confusion)

- `"41"` (string) is two ASCII bytes: `0x34 0x31`.
- `0x41` (byte value) is `A` (decimal `65)`.
  
```go
[]byte("41")   // [0x34 0x31]
[]byte{0x41}   // "A"
```

## Conversions (correct patterns)

### String ↔ Bytes (UTF-8 bytes of the string)

```go
s := "€"
b := []byte(s)         // UTF-8 bytes: [0xE2, 0x82, 0xAC]
s2 := string(b)        // reconstructs the string from UTF-8 bytes
```

#### Iterate runes (decode UTF-8):

```go
for _, r := range s { /* r is rune */ }
```

### Decode one rune from bytes:

```go
r, size := utf8.DecodeRune(b[i:])    // size in bytes (1–4)
```

#### Encode rune to UTF-8 bytes:

```go
buf := make([]byte, 4)
n := utf8.EncodeRune(buf, '€')       // n == 3; use buf[:n]
```

#### Via string (simple)

```go
bs := []byte(string('€'))            // E2 82 AC
rs := []rune("€")                    // [0x20AC]
```


## Conversions (**WHAT NOT TO DO**)

- **Wrong**: Treating cast as decode/encode:

```go
r := rune(b)        // only numeric widen; OK for ASCII, NOT UTF-8 decode
b := byte(r)        // truncates to low 8 bits; safe only for ASCII runes
```

- **Wrong**: `[]byte([]rune("…"))` (nonsense; encodes runes as 4-byte int32 values, not UTF-8).

Use `utf8.EncodeRune` or `string(r)` -> `[]byte`.


## Length & Counting

```go
len(s)                     // bytes in UTF-8
utf8.RuneCountInString(s)  // runes (code points)

utf8.ValidString(s)        // is s valid UTF-8?
```

### Iterate correctly

By bytes (raw, fast, safe for arbitrary data):

```go
for i := 0; i < len(b); i++ {
    _ = b[i] // one raw byte
}
```

By runes (text-aware):

```go
for i, r := range s {
    _ = i    // byte offset in s
    _ = r    // Unicode code point
}
```

## ASCII-only helpers (recommended for low-level HTTP)

If you know the data is ASCII (e.g., percent-encoding, header tokens), byte-wise helpers are simplest and fastest.

```go
func isHexDigitASCII(b byte) bool {
    return ('0' <= b && b <= '9') ||
           ('a' <= b && b <= 'f') ||
           ('A' <= b && b <= 'F')
}

func isLetterASCII(b byte) bool {
    return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

func isAlphanumASCII(b byte) bool {
    return isLetterASCII(b) || ('0' <= b && b <= '9')
}

// All ASCII special characters (punctuation + symbols)
func isSpecialCharASCII(b byte) bool {
    return (b >= 0x21 && b <= 0x2F) || // !"#$%&'()*+,-./
           (b >= 0x3A && b <= 0x40) || // :;<=>?@
           (b >= 0x5B && b <= 0x60) || // [\]^_`
           (b >= 0x7B && b <= 0x7E)    // {|}~
}
```

> If you need to accept both byte and rune easily, either accept a rune and cast bytes at the call site (after an ASCII check), or write a tiny generic helper with a union type set (~byte | ~rune).

## Percent-encoding (URL-encoding) of raw bytes

Encode each byte to %XX:

```go
var hex = []byte("0123456789ABCDEF")

// URLEncodeAll encodes each character in the input string to its percent-encoded representation
// It handles UTF-8 characters by encoding each byte of their UTF-8 representation
// Uses zero-copy string indexing for optimal performance
func URLEncodeAll(s string) string {
	if len(s) == 0 {
		return ""
	}

	dst := make([]byte, len(s)*3)
	j := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		dst[j] = '%'
		dst[j+1] = hexChars[b>>4]
		dst[j+2] = hexChars[b&0x0F]
		j += 3
	}
	return string(dst)
}
```


## Normalization vs "Confusables"

- Normalization (NFC/NFD/NFKC/NFKD) changes Unicode composition/compatibility; use only if you want canonical forms.
- Confusables (homoglyphs) are look-alike characters from different scripts.
- Replacing ASCII with confusables is not normalization; it’s homoglyph substitution. ???

## Pitfalls & Gotchas

- `len(s)` is bytes, not characters.
- Casting `rune→byte` loses data unless ASCII.
- Converting `[]byte` with invalid UTF-8 to `string` keeps those bytes; ranging over the string yields `U+FFFD` for invalid sequences.
- `unicode.Is…` funcs consult Unicode tables; if you only need ASCII, stick to byte comparisons for speed and determinism.
- Don’t mix up hex strings `("41")` with byte values `(0x41)`.


## Handy Snippets

### Count runes:

```go
n := utf8.RuneCountInString(s)
```

### Validate UTF-8:

```go
ok := utf8.ValidString(s)
```

### Decode with fallback:

```go
for i := 0; i < len(b); {
    r, sz := utf8.DecodeRune(b[i:])
    if r == utf8.RuneError && sz == 1 {
        // invalid byte; handle as you wish
    }
    i += sz
}
```

### Encode a rune:

```go
var tmp [4]byte
n := utf8.EncodeRune(tmp[:], r) // use tmp[:n]
```

## When to use what

- `[]byte`: I/O, wire formats, hashing, exact control (security tools).
- `string`: general text APIs; convert to bytes when sending/receiving.
- `rune` / `[]rune`: when you must operate on code points (case mapping, classification, Unicode-aware iteration).


## Snippet code to print ...

```go
package main

import (
	"fmt"
	"unicode"
)

func printRuneWithHex(r rune) {
	fmt.Printf("%q(\\x%02X) ", r, r)
}

func main() {
	fmt.Println("Punctuation runes (basic ASCII range):")
	for r := rune(0); r <= 127; r++ {
		if unicode.IsPunct(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nPunctuation runes (extended sample up to 0xFF):")
	for r := rune(0); r <= 255; r++ {
		if unicode.IsPunct(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nLetter runes (basic ASCII range):")
	for r := rune(0); r <= 127; r++ {
		if unicode.IsLetter(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nLetter runes (extended ASCII range):")
	for r := rune(128); r <= 255; r++ {
		if unicode.IsLetter(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nControl runes (basic ASCII range):")
	for r := rune(0); r <= 127; r++ {
		if unicode.IsControl(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nControl runes (extended ASCII range):")
	for r := rune(128); r <= 255; r++ {
		if unicode.IsControl(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nSymbol runes (extended ASCII range):")
	for r := rune(0); r <= 255; r++ {
		if unicode.IsSymbol(r) {
			printRuneWithHex(r)
		}
	}

	fmt.Println("\n\nWhite space runes (extended ASCII range):")
	for r := rune(0); r <= 255; r++ {
		if unicode.IsSpace(r) {
			printRuneWithHex(r)
		}
	}
}
```

Sample output:

```go
Punctuation runes (basic ASCII range):
'!'(\x21) '"'(\x22) '#'(\x23) '%'(\x25) '&'(\x26) '\''(\x27) '('(\x28) ')'(\x29) '*'(\x2A) ','(\x2C) '-'(\x2D) '.'(\x2E) '/'(\x2F) ':'(\x3A) ';'(\x3B) '?'(\x3F) '@'(\x40) '['(\x5B) '\\'(\x5C) ']'(\x5D) '_'(\x5F) '{'(\x7B) '}'(\x7D) 

Punctuation runes (extended sample up to 0xFF):
'!'(\x21) '"'(\x22) '#'(\x23) '%'(\x25) '&'(\x26) '\''(\x27) '('(\x28) ')'(\x29) '*'(\x2A) ','(\x2C) '-'(\x2D) '.'(\x2E) '/'(\x2F) ':'(\x3A) ';'(\x3B) '?'(\x3F) '@'(\x40) '['(\x5B) '\\'(\x5C) ']'(\x5D) '_'(\x5F) '{'(\x7B) '}'(\x7D) '¡'(\xA1) '§'(\xA7) '«'(\xAB) '¶'(\xB6) '·'(\xB7) '»'(\xBB) '¿'(\xBF) 

Control runes (basic ASCII range):
'\x00'(\x00) '\x01'(\x01) '\x02'(\x02) '\x03'(\x03) '\x04'(\x04) '\x05'(\x05) '\x06'(\x06) '\a'(\x07) '\b'(\x08) '\t'(\x09) '\n'(\x0A) '\v'(\x0B) '\f'(\x0C) '\r'(\x0D) '\x0e'(\x0E) '\x0f'(\x0F) '\x10'(\x10) '\x11'(\x11) '\x12'(\x12) '\x13'(\x13) '\x14'(\x14) '\x15'(\x15) '\x16'(\x16) '\x17'(\x17) '\x18'(\x18) '\x19'(\x19) '\x1a'(\x1A) '\x1b'(\x1B) '\x1c'(\x1C) '\x1d'(\x1D) '\x1e'(\x1E) '\x1f'(\x1F) '\x7f'(\x7F) 

Control runes (extended ASCII range):
'\u0080'(\x80) '\u0081'(\x81) '\u0082'(\x82) '\u0083'(\x83) '\u0084'(\x84) '\u0085'(\x85) '\u0086'(\x86) '\u0087'(\x87) '\u0088'(\x88) '\u0089'(\x89) '\u008a'(\x8A) '\u008b'(\x8B) '\u008c'(\x8C) '\u008d'(\x8D) '\u008e'(\x8E) '\u008f'(\x8F) '\u0090'(\x90) '\u0091'(\x91) '\u0092'(\x92) '\u0093'(\x93) '\u0094'(\x94) '\u0095'(\x95) '\u0096'(\x96) '\u0097'(\x97) '\u0098'(\x98) '\u0099'(\x99) '\u009a'(\x9A) '\u009b'(\x9B) '\u009c'(\x9C) '\u009d'(\x9D) '\u009e'(\x9E) '\u009f'(\x9F) 

Symbol runes (extended ASCII range):
'$'(\x24) '+'(\x2B) '<'(\x3C) '='(\x3D) '>'(\x3E) '^'(\x5E) '`'(\x60) '|'(\x7C) '~'(\x7E) '¢'(\xA2) '£'(\xA3) '¤'(\xA4) '¥'(\xA5) '¦'(\xA6) '¨'(\xA8) '©'(\xA9) '¬'(\xAC) '®'(\xAE) '¯'(\xAF) '°'(\xB0) '±'(\xB1) '´'(\xB4) '¸'(\xB8) '×'(\xD7) '÷'(\xF7) 

White space runes (extended ASCII range):
'\t'(\x09) '\n'(\x0A) '\v'(\x0B) '\f'(\x0C) '\r'(\x0D) ' '(\x20) '\u0085'(\x85) '\u00a0'(\xA0) 
```

## Snippet two ...

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {

	for r := rune(0); r <= 0xFF; r++ {
		switch {
		case unicode.IsControl(r):
			fmt.Printf("CTRL %q (U+%04X)\n", r, r)
		case unicode.IsPunct(r):
			fmt.Printf("PUNCT %q (U+%04X)\n", r, r)
		case unicode.IsLetter(r):
			fmt.Printf("LETTER %q (U+%04X)\n", r, r)
		}
	}

}
```

Sample output

```go
CTRL '\x00' (U+0000)
CTRL '\x01' (U+0001)
CTRL '\x02' (U+0002)
CTRL '\x03' (U+0003)
CTRL '\x04' (U+0004)
CTRL '\x05' (U+0005)
CTRL '\x06' (U+0006)
CTRL '\a' (U+0007)
CTRL '\b' (U+0008)
CTRL '\t' (U+0009)
CTRL '\n' (U+000A)
CTRL '\v' (U+000B)
CTRL '\f' (U+000C)
CTRL '\r' (U+000D)
CTRL '\x0e' (U+000E)
CTRL '\x0f' (U+000F)
CTRL '\x10' (U+0010)
CTRL '\x11' (U+0011)
CTRL '\x12' (U+0012)
CTRL '\x13' (U+0013)
CTRL '\x14' (U+0014)
CTRL '\x15' (U+0015)
CTRL '\x16' (U+0016)
CTRL '\x17' (U+0017)
CTRL '\x18' (U+0018)
CTRL '\x19' (U+0019)
CTRL '\x1a' (U+001A)
CTRL '\x1b' (U+001B)
CTRL '\x1c' (U+001C)
CTRL '\x1d' (U+001D)
CTRL '\x1e' (U+001E)
CTRL '\x1f' (U+001F)
PUNCT '!' (U+0021)
PUNCT '"' (U+0022)
PUNCT '#' (U+0023)
PUNCT '%' (U+0025)
PUNCT '&' (U+0026)
PUNCT '\'' (U+0027)
PUNCT '(' (U+0028)
PUNCT ')' (U+0029)
PUNCT '*' (U+002A)
PUNCT ',' (U+002C)
PUNCT '-' (U+002D)
PUNCT '.' (U+002E)
PUNCT '/' (U+002F)
PUNCT ':' (U+003A)
PUNCT ';' (U+003B)
PUNCT '?' (U+003F)
PUNCT '@' (U+0040)
LETTER 'A' (U+0041)
LETTER 'B' (U+0042)
LETTER 'C' (U+0043)
LETTER 'D' (U+0044)
LETTER 'E' (U+0045)
LETTER 'F' (U+0046)
LETTER 'G' (U+0047)
LETTER 'H' (U+0048)
LETTER 'I' (U+0049)
LETTER 'J' (U+004A)
LETTER 'K' (U+004B)
LETTER 'L' (U+004C)
LETTER 'M' (U+004D)
LETTER 'N' (U+004E)
LETTER 'O' (U+004F)
LETTER 'P' (U+0050)
LETTER 'Q' (U+0051)
LETTER 'R' (U+0052)
LETTER 'S' (U+0053)
LETTER 'T' (U+0054)
LETTER 'U' (U+0055)
LETTER 'V' (U+0056)
LETTER 'W' (U+0057)
LETTER 'X' (U+0058)
LETTER 'Y' (U+0059)
LETTER 'Z' (U+005A)
PUNCT '[' (U+005B)
PUNCT '\\' (U+005C)
PUNCT ']' (U+005D)
PUNCT '_' (U+005F)
LETTER 'a' (U+0061)
LETTER 'b' (U+0062)
LETTER 'c' (U+0063)
LETTER 'd' (U+0064)
LETTER 'e' (U+0065)
LETTER 'f' (U+0066)
LETTER 'g' (U+0067)
LETTER 'h' (U+0068)
LETTER 'i' (U+0069)
LETTER 'j' (U+006A)
LETTER 'k' (U+006B)
LETTER 'l' (U+006C)
LETTER 'm' (U+006D)
LETTER 'n' (U+006E)
LETTER 'o' (U+006F)
LETTER 'p' (U+0070)
LETTER 'q' (U+0071)
LETTER 'r' (U+0072)
LETTER 's' (U+0073)
LETTER 't' (U+0074)
LETTER 'u' (U+0075)
LETTER 'v' (U+0076)
LETTER 'w' (U+0077)
LETTER 'x' (U+0078)
LETTER 'y' (U+0079)
LETTER 'z' (U+007A)
PUNCT '{' (U+007B)
PUNCT '}' (U+007D)
CTRL '\x7f' (U+007F)
CTRL '\u0080' (U+0080)
CTRL '\u0081' (U+0081)
CTRL '\u0082' (U+0082)
CTRL '\u0083' (U+0083)
CTRL '\u0084' (U+0084)
CTRL '\u0085' (U+0085)
CTRL '\u0086' (U+0086)
CTRL '\u0087' (U+0087)
CTRL '\u0088' (U+0088)
CTRL '\u0089' (U+0089)
CTRL '\u008a' (U+008A)
CTRL '\u008b' (U+008B)
CTRL '\u008c' (U+008C)
CTRL '\u008d' (U+008D)
CTRL '\u008e' (U+008E)
CTRL '\u008f' (U+008F)
CTRL '\u0090' (U+0090)
CTRL '\u0091' (U+0091)
CTRL '\u0092' (U+0092)
CTRL '\u0093' (U+0093)
CTRL '\u0094' (U+0094)
CTRL '\u0095' (U+0095)
CTRL '\u0096' (U+0096)
CTRL '\u0097' (U+0097)
CTRL '\u0098' (U+0098)
CTRL '\u0099' (U+0099)
CTRL '\u009a' (U+009A)
CTRL '\u009b' (U+009B)
CTRL '\u009c' (U+009C)
CTRL '\u009d' (U+009D)
CTRL '\u009e' (U+009E)
CTRL '\u009f' (U+009F)
PUNCT '¡' (U+00A1)
PUNCT '§' (U+00A7)
LETTER 'ª' (U+00AA)
PUNCT '«' (U+00AB)
LETTER 'µ' (U+00B5)
PUNCT '¶' (U+00B6)
PUNCT '·' (U+00B7)
LETTER 'º' (U+00BA)
PUNCT '»' (U+00BB)
PUNCT '¿' (U+00BF)
LETTER 'À' (U+00C0)
LETTER 'Á' (U+00C1)
LETTER 'Â' (U+00C2)
LETTER 'Ã' (U+00C3)
LETTER 'Ä' (U+00C4)
LETTER 'Å' (U+00C5)
LETTER 'Æ' (U+00C6)
LETTER 'Ç' (U+00C7)
LETTER 'È' (U+00C8)
LETTER 'É' (U+00C9)
LETTER 'Ê' (U+00CA)
LETTER 'Ë' (U+00CB)
LETTER 'Ì' (U+00CC)
LETTER 'Í' (U+00CD)
LETTER 'Î' (U+00CE)
LETTER 'Ï' (U+00CF)
LETTER 'Ð' (U+00D0)
LETTER 'Ñ' (U+00D1)
LETTER 'Ò' (U+00D2)
LETTER 'Ó' (U+00D3)
LETTER 'Ô' (U+00D4)
LETTER 'Õ' (U+00D5)
LETTER 'Ö' (U+00D6)
LETTER 'Ø' (U+00D8)
LETTER 'Ù' (U+00D9)
LETTER 'Ú' (U+00DA)
LETTER 'Û' (U+00DB)
LETTER 'Ü' (U+00DC)
LETTER 'Ý' (U+00DD)
LETTER 'Þ' (U+00DE)
LETTER 'ß' (U+00DF)
LETTER 'à' (U+00E0)
LETTER 'á' (U+00E1)
LETTER 'â' (U+00E2)
LETTER 'ã' (U+00E3)
LETTER 'ä' (U+00E4)
LETTER 'å' (U+00E5)
LETTER 'æ' (U+00E6)
LETTER 'ç' (U+00E7)
LETTER 'è' (U+00E8)
LETTER 'é' (U+00E9)
LETTER 'ê' (U+00EA)
LETTER 'ë' (U+00EB)
LETTER 'ì' (U+00EC)
LETTER 'í' (U+00ED)
LETTER 'î' (U+00EE)
LETTER 'ï' (U+00EF)
LETTER 'ð' (U+00F0)
LETTER 'ñ' (U+00F1)
LETTER 'ò' (U+00F2)
LETTER 'ó' (U+00F3)
LETTER 'ô' (U+00F4)
LETTER 'õ' (U+00F5)
LETTER 'ö' (U+00F6)
LETTER 'ø' (U+00F8)
LETTER 'ù' (U+00F9)
LETTER 'ú' (U+00FA)
LETTER 'û' (U+00FB)
LETTER 'ü' (U+00FC)
LETTER 'ý' (U+00FD)
LETTER 'þ' (U+00FE)
LETTER 'ÿ' (U+00FF)
```



## Resources

- https://pkg.go.dev/unicode/utf8
- https://go.dev/src/unicode/utf8/utf8.go