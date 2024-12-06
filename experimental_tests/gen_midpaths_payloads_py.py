import argparse
from urllib.parse import urlparse
from pathlib import Path
import re
import sys

# Custom Helper to validate the alg generators between go and python
def replacenth(string, sub, wanted, n):
    matches = [m.start() for m in re.finditer(re.escape(sub), string)]
    if n >= len(matches):
        return string  # If n is out of bounds, return the original string
    where = matches[n]
    return string[:where] + string[where:].replace(sub, wanted, 1)


def read_payloads_file(file_path):
    payloads = []
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                payloads.append(line)
    return payloads


def generate_payloads(base_url, payloads):

    parsed_url = urlparse(base_url)
    base_path = parsed_url.path
    if not base_path:
        base_path = "/"

    slash_count = max(base_path.count("/"), 1)

    generated_payloads = set()
    for idx_slash in range(slash_count):
        for internal_payload in payloads:
            # Generate `path_post` variants
            path_post = replacenth(base_path, "/", f"/{internal_payload}", idx_slash)
            generated_payloads.add(f"{parsed_url.scheme}://{parsed_url.netloc}{path_post}")
            generated_payloads.add(f"{parsed_url.scheme}://{parsed_url.netloc}/{path_post}")

            # Generate `path_pre` variants for indices greater than 1
            if idx_slash > 1:
                path_pre = replacenth(base_path, "/", f"{internal_payload}/", idx_slash)
                generated_payloads.add(f"{parsed_url.scheme}://{parsed_url.netloc}{path_pre}")
                generated_payloads.add(f"{parsed_url.scheme}://{parsed_url.netloc}/{path_pre}")

    return generated_payloads


def main():
    parser = argparse.ArgumentParser(description="Generate payloads for mid-path bypass testing.")
    parser.add_argument("-u", "--url", required=True, help="Base target URL.")
    parser.add_argument("-p", "--payloads-file", default="../payloads/internal_midpaths.lst",
                        help="Path to the payloads file.")
    args = parser.parse_args()

    # Resolve payloads file path
    payloads_file = Path(args.payloads_file).resolve()
    if not payloads_file.exists():
        print(f"Error: Payloads file not found at {payloads_file}")
        exit(1)

    payloads = read_payloads_file(payloads_file)
    generated_payloads = generate_payloads(args.url, payloads)

    # Ensure consistent output encoding
    for payload in sorted(generated_payloads):
        try:
            payload_bytes = payload.encode('utf-8')
            print(payload_bytes.decode('utf-8'))
        except UnicodeEncodeError:
            print(payload_bytes)

    print(f"\nTotal Payloads Generated: {len(generated_payloads)}")

if __name__ == "__main__":
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    main()