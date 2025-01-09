package bytebufferpool_test

import (
	"fmt"

	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp/bytebufferpool"
)

func ExampleByteBuffer() {
	bb := bytebufferpool.Get()

	bb.WriteString("first line\n")
	bb.Write([]byte("second line\n"))
	bb.B = append(bb.B, "third line\n"...)

	fmt.Printf("bytebuffer contents=%q", bb.B)

	// It is safe to release byte buffer now, since it is
	// no longer used.
	bytebufferpool.Put(bb)
}
