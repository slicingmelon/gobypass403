# Unicode Character Mapping Tools

This directory contains two specialized tools for generating comprehensive JSON maps of Unicode characters that can be used for WAF/firewall bypass testing. Each tool targets different Unicode vulnerabilities and bypass techniques.

## Tools Overview

### 1. Unicode Normalization Tool (`unicode_normalizatio_nmap.go`)
Located in `unicode-normalization-map/`

**Purpose**: Finds Unicode characters that normalize to target characters using Unicode normalization forms.

**How it works**: Scans the entire Unicode range (up to `0x10FFFF`) and uses four different normalization forms (`NFKC`, `NFKD`, `NFC`, `NFD`) to identify characters that normalize to your target range.

**Use cases**: 
- Applications that normalize Unicode input before processing
- WAFs that apply Unicode normalization before filtering
- Systems vulnerable to Unicode normalization attacks

### 2. Unicode Truncation Tool (`unicode_truncation_map.go`) 
Located in `unicode-truncation-map/`

**Purpose**: Finds Unicode characters that truncate to target characters via byte truncation.

**How it works**: Identifies characters where the low byte (`char & 0xFF`) matches your target range, effectively finding characters that "truncate" to target bytes.

**Use cases**:
- Applications that truncate Unicode to single bytes
- Systems that only check the low byte of characters
- WAFs vulnerable to byte truncation attacks

## Key Differences

| Aspect | Normalization Tool | Truncation Tool |
|--------|-------------------|-----------------|
| **Target Range** | ASCII printable (0x20-0x7F) | ALL bytes (0x00-0xFF) |
| **Technique** | Unicode normalization | Byte truncation |
| **Vulnerability** | Apps that normalize Unicode | Apps that truncate to low byte |

## Command-Line Flags

### Unicode Normalization Tool
| Flag          | Description                                                              | Default                           |
|---------------|--------------------------------------------------------------------------|-----------------------------------|
| `--range`     | The target character range to generate mappings for (e.g., `0-255`).     | `0-127`                          |
| `--max-norms` | Maximum number of normalization mappings per character (0 for unlimited). | `0`                              |
| `--output`    | Output file name for the JSON map.                                       | `unicode_normalization_map.json` |

### Unicode Truncation Tool  
| Flag          | Description                                                              | Default                        |
|---------------|--------------------------------------------------------------------------|--------------------------------|
| `--range`     | The target character range to generate mappings for (e.g., `0-255`).     | `0-127`                       |
| `--max-trunc` | Maximum number of truncation mappings per character (0 for unlimited).   | `0`                           |
| `--output`    | Output file name for the JSON map.                                       | `unicode_truncation_map.json` |

## Usage Examples

### Unicode Normalization Tool

1.  **Generate normalization mappings for ASCII characters (0-127):**
    ```sh
    cd unicode-normalization-map/
    go run unicode_normalizatio_nmap.go --range "0-127" --max-norms 5 --output ascii_norm.json
    ```

2.  **Generate normalization mappings for printable ASCII (32-126):**
    ```sh
    cd unicode-normalization-map/
    go run unicode_normalizatio_nmap.go --range "32-126" --output printable_norm.json
    ```

3.  **Generate mappings for uppercase letters (A-Z, values 65-90):**
    ```sh
    cd unicode-normalization-map/
    go run unicode_normalizatio_nmap.go --range "65-90" --max-norms 3 --output uppercase_norm.json
    ```

### Unicode Truncation Tool

1.  **Generate truncation mappings for ASCII characters (0-127):**
    ```sh
    cd unicode-truncation-map/
    go run unicode_truncation_map.go --range "0-127" --max-trunc 4 --output ascii_trunc.json
    ```

2.  **Generate truncation mappings for extended ASCII (0-255):**
    ```sh
    cd unicode-truncation-map/
    go run unicode_truncation_map.go --range "0-255" --output extended_trunc.json
    ```

3.  **Generate truncation mappings for path characters only:**
    ```sh
    cd unicode-truncation-map/
    go run unicode_truncation_map.go --range "46-47" --max-trunc 5 --output path_chars_trunc.json
    ```

## Sample JSON Output

Both tools produce JSON arrays where each object represents a target character from your specified range. The structure is identical, but the `form` field distinguishes between the two types:

- **Normalization mappings**: `"NFKC"`, `"NFKD"`, `"NFC"`, `"NFD"`
- **Truncation mappings**: `"TRUNCATION"`

### Unicode Normalization Tool Example

Sample entry for character `2` (ASCII 50) showing various Unicode characters that normalize to `2`:

```json
{
  "ascii": 50,
  "char": "2",
  "mappings": [
    {
      "unicode": "2",
      "utf8_bytes": "\\x32",
      "url_encoded": "%32",
      "normalizes_as": "2",
      "normalizes_as_hex": "\\x32",
      "form": "NFKC"
    },
    {
      "unicode": "²",
      "utf8_bytes": "\\xC2\\xB2",
      "url_encoded": "%C2%B2",
      "normalizes_as": "2",
      "normalizes_as_hex": "\\x32",
      "form": "NFKC"
    },
    {
      "unicode": "₂",
      "utf8_bytes": "\\xE2\\x82\\x82",
      "url_encoded": "%E2%82%82",
      "normalizes_as": "2",
      "normalizes_as_hex": "\\x32",
      "form": "NFKC"
    },
    {
      "unicode": "②",
      "utf8_bytes": "\\xE2\\x91\\xA1",
      "url_encoded": "%E2%91%A1",
      "normalizes_as": "2",
      "normalizes_as_hex": "\\x32",
      "form": "NFKC"
    },
    {
      "unicode": "２",
      "utf8_bytes": "\\xEF\\xBC\\x92",
      "url_encoded": "%EF%BC%92",
      "normalizes_as": "2",
      "normalizes_as_hex": "\\x32",
      "form": "NFKC"
    }
  ]
}
```

### Unicode Truncation Tool Example

Sample entry for character byte `0x00` showing Unicode characters whose low byte truncates to `0x00`:

```json
{
  "ascii": 0,
  "char": "\\0",
  "mappings": [
    {
      "unicode": "Ā",
      "utf8_bytes": "\\xC4\\x80",
      "url_encoded": "%C4%80",
      "normalizes_as": "\\0",
      "normalizes_as_hex": "\\x00",
      "form": "TRUNCATION"
    },
    {
      "unicode": "Ȁ",
      "utf8_bytes": "\\xC8\\x80",
      "url_encoded": "%C8%80",
      "normalizes_as": "\\0",
      "normalizes_as_hex": "\\x00",
      "form": "TRUNCATION"
    },
    {
      "unicode": "̀",
      "utf8_bytes": "\\xCC\\x80",
      "url_encoded": "%CC%80",
      "normalizes_as": "\\0",
      "normalizes_as_hex": "\\x00",
      "form": "TRUNCATION"
    },
    {
      "unicode": "Ѐ",
      "utf8_bytes": "\\xD0\\x80",
      "url_encoded": "%D0%80",
      "normalizes_as": "\\0",
      "normalizes_as_hex": "\\x00",
      "form": "TRUNCATION"
    }
  ]
}
```

## Integration with Bypass Modules

These JSON files can be used directly in your bypass modules. Filter by the `form` field to use specific mapping types:

```go
// Use only normalization mappings  
for _, mapping := range mappings {
    if mapping.Form != "TRUNCATION" {
        // Handle normalization mappings (NFKC, NFKD, etc.)
    }
}

// Use only truncation mappings
for _, mapping := range mappings {
    if mapping.Form == "TRUNCATION" {
        // Handle truncation mappings
    }
}
```

