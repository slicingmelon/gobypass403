# unicodecharmap.go

This tool generates a comprehensive JSON map of Unicode characters that normalize to a specified range of target characters (e.g., ASCII). This map is invaluable for security testing, particularly for discovering WAF/firewall bypasses that rely on Unicode normalization vulnerabilities.

The tool scans the entire Unicode range (up to `0x10FFFF`) and uses four different normalization forms (`NFKC`, `NFKD`, `NFC`, `NFD`) to find equivalent characters.

## Features

-   **Custom Character Ranges**: Generate mappings for any character range, not just standard ASCII.
-   **Normalization Limit**: Control the size of the output by limiting the number of mappings per character.
-   **Custom Output File**: Specify the name for the generated JSON file.
-   **Full Unicode Scan**: Scans all 1,114,112 Unicode code points for maximum coverage.

## Command-Line Flags

| Flag          | Description                                                              | Default                  |
|---------------|--------------------------------------------------------------------------|--------------------------|
| `--range`     | The target character range to generate mappings for (e.g., `0-255`).     | `0-127`                  |
| `--max-norms` | Maximum number of normalization mappings per character (0 for unlimited). | `0`                      |
| `--output`    | Output file name for the JSON map.                                       | `unicode_char_map.json`  |

## Usage Examples

1.  **Generate a default map for ASCII characters (0-127) with unlimited mappings:**
    ```sh
    go run unicodecharmap.go
    ```

2.  **Generate a map for the extended ASCII range (0-255) and save it to a different file:**
    ```sh
    go run unicodecharmap.go --range 0-255 --output extended_ascii_map.json
    ```

3.  **Generate a map for uppercase letters (A-Z, values 65-90), limiting the results to the first 5 mappings found for each letter:**
    ```sh
    go run unicodecharmap.go --range 65-90 --max-norms 5 --output uppercase_top5.json
    ```

## Sample JSON Output

The output is a JSON array where each object represents a target character from your specified range that has at least one Unicode normalization mapping.

Here is a sample entry for the character `E` (value 69):

```json
 {
    "value": 69,
    "char": "E",
    "mappings": [
      {
        "unicode": "E",
        "utf8_bytes": "\\x45",
        "url_encoded": "%45",
        "normalizes_as": "E",
        "normalizes_as_hex": "\\x45",
        "form": "NFKC"
      },
      {
        "unicode": "ᴱ",
        "utf8_bytes": "\\xE1\\xB4\\xB1",
        "url_encoded": "%E1%B4%B1",
        "normalizes_as": "E",
        "normalizes_as_hex": "\\x45",
        "form": "NFKC"
      },
      {
        "unicode": "ℰ",
        "utf8_bytes": "\\xE2\\x84\\xB0",
        "url_encoded": "%E2%84%B0",
        "normalizes_as": "E",
        "normalizes_as_hex": "\\x45",
        "form": "NFKC"
      },
      {
        "unicode": "Ⓔ",
        "utf8_bytes": "\\xE2\\x92\\xBA",
        "url_encoded": "%E2%92%BA",
        "normalizes_as": "E",
        "normalizes_as_hex": "\\x45",
        "form": "NFKC"
      },
      {
        "unicode": "Ｅ",
        "utf8_bytes": "\\xEF\\xBC\\xA5",
        "url_encoded": "%EF%BC%A5",
        "normalizes_as": "E",
        "normalizes_as_hex": "\\x45",
        "form": "NFKC"
      }
    ]
  }
```

