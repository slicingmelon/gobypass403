# Go Text & Bytes Cheatsheet

A compact, practical reference for working with bytes, strings, and runes in Go, plus the right (and wrong) ways to convert between them.

## TL;DR

- byte = uint8 (0–255). A []byte is raw bytes; it doesn’t “know” text.
- string = immutable sequence of bytes (by convention UTF-8).
- rune = int32 Unicode code point (not “UTF-8 char”).

```go
len("a")   == 1                 // 0x61
len("€")   == 3                 // E2 82 AC (UTF-8)
len("你")  == 3                 // UTF-8 length, not “characters”
utf8.RuneCountInString("€") == 1
```

**Casting isn’t encoding/decoding.**

`byte(x)` / `rune(x)` only change numeric types. To go between runes and UTF-8 bytes, encode/decode.

## Types at a glance

Type	Meaning	Notes
byte	alias of uint8	One raw byte
[]byte	byte slice	Raw buffer; I/O, hashing, sockets
string	sequence of bytes (UTF-8 by conv.)	Immutable; may contain invalid UTF-8
rune	alias of int32 (Unicode codepoint)	Logical “character”; not UTF-8 length
[]rune	slice of runes	One element per code point


## Bytes vs Hex string (common confusion)

- "41" (string) is two ASCII bytes: 0x34 0x31.
- 0x41 (byte value) is 'A' (decimal 65).
  
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


## Conversions (what not to do)

- Wrong: Treating cast as decode/encode:

```go
r := rune(b)        // only numeric widen; OK for ASCII, NOT UTF-8 decode
b := byte(r)        // truncates to low 8 bits; safe only for ASCII runes
```

- Wrong: []byte([]rune("…")) (nonsense; encodes runes as 4-byte int32 values, not UTF-8).

Use `utf8.EncodeRune` or `string(r)` → `[]byte`.


## Length & counting

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

func isAlnumASCII(b byte) bool {
    return isLetterASCII(b) || ('0' <= b && b <= '9')
}
```

> If you need to accept both byte and rune easily, either accept a rune and cast bytes at the call site (after an ASCII check), or write a tiny generic helper with a union type set (~byte | ~rune).

## Percent-encoding (URL-encoding) of raw bytes

Encode each byte to %XX:

```go
var hex = []byte("0123456789ABCDEF")

func URLEncodeAll(s string) string {
    in := []byte(s)            // UTF-8 bytes of s
    out := make([]byte, 0, len(in)*3)
    for _, b := range in {
        out = append(out, '%', hex[b>>4], hex[b&0x0F])
    }
    return string(out)
}
```


## Normalization vs “confusables”

- Normalization (NFC/NFD/NFKC/NFKD) changes Unicode composition/compatibility; use only if you want canonical forms.
- Confusables (homoglyphs) are look-alike characters from different scripts.
- Replacing ASCII with confusables is not normalization; it’s homoglyph substitution. ???

## Pitfalls & gotchas

- `len(s)` is bytes, not characters.
- Casting `rune→byte` loses data unless ASCII.
- Converting `[]byte` with invalid UTF-8 to `string` keeps those bytes; ranging over the string yields `U+FFFD` for invalid sequences.
- `unicode.Is…` funcs consult Unicode tables; if you only need ASCII, stick to byte comparisons for speed and determinism.
- Don’t mix up hex strings `("41")` with byte values `(0x41)`.


## Handy snippets

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


## Resources

- https://pkg.go.dev/unicode/utf8
- https://go.dev/src/unicode/utf8/utf8.go
