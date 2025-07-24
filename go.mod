module github.com/slicingmelon/gobypass403

go 1.24.1

require (
	fortio.org/progressbar v1.1.0
	github.com/VictoriaMetrics/fastcache v1.12.5
	github.com/alitto/pond/v2 v2.5.0
	github.com/andybalholm/brotli v1.2.0
	github.com/dgraph-io/ristretto/v2 v2.2.0
	github.com/golang/snappy v1.0.0
	github.com/klauspost/compress v1.18.0
	github.com/likexian/doh v0.7.1
	github.com/mattn/go-sqlite3 v1.14.29
	github.com/phuslu/fastdns v0.12.5
	github.com/pierrec/lz4/v4 v4.1.22
	github.com/pterm/pterm v0.12.81
	github.com/refraction-networking/utls v1.8.0
	github.com/slicingmelon/go-bytesutil v0.0.1
	github.com/slicingmelon/go-rawurlparser v0.3.1
	github.com/stretchr/testify v1.10.0
	github.com/valyala/fasthttp v1.64.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
	golang.org/x/text v0.27.0
)

require (
	atomicgo.dev/cursor v0.2.0 // indirect
	atomicgo.dev/keyboard v0.2.9 // indirect
	atomicgo.dev/schedule v0.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/containerd/console v1.0.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/likexian/gokit v0.25.15 // indirect
	github.com/lithammer/fuzzysearch v1.1.8 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/term v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/valyala/fasthttp => ./pkg/fasthttp-1.62.0
