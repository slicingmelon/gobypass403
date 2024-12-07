# Best Practices

- Do not allocate objects and []byte buffers - just reuse them as much as possible. Fasthttp API design encourages this.
- sync.Pool is your best friend.
- Profile your program in production. go tool pprof --alloc_objects your-program mem.pprof usually gives better insights for optimization opportunities than go tool pprof your-program cpu.pprof.
- Write tests and benchmarks for hot paths.
- Avoid conversion between []byte and string, since this may result in memory allocation+copy. Fasthttp API provides functions for both []byte and string - use these functions instead of converting manually between []byte and string. There are some exceptions - see this wiki page for more details.
- Verify your tests and production code under race detector on a regular basis.
- Prefer quicktemplate instead of html/template in your webserver.

# Tricks with []byte buffers

## Important points:

- Fasthttp works with [RequestHandler functions](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHandler)
- instead of objects implementing [Handler interface](https://pkg.go.dev/net/http#Handler).
- Fortunately, it is easy to pass bound struct methods to fasthttp:

```go
type MyHandler struct {
  	foobar string
  }

  // request handler in net/http style, i.e. method bound to MyHandler struct.
  func (h *MyHandler) HandleFastHTTP(ctx *fasthttp.RequestCtx) {
  	// notice that we may access MyHandler properties here - see h.foobar.
  	fmt.Fprintf(ctx, "Hello, world! Requested path is %q. Foobar is %q",
  		ctx.Path(), h.foobar)
  }

  // request handler in fasthttp style, i.e. just plain function.
  func fastHTTPHandler(ctx *fasthttp.RequestCtx) {
  	fmt.Fprintf(ctx, "Hi there! RequestURI is %q", ctx.RequestURI())
  }

  // pass bound struct method to fasthttp
  myHandler := &MyHandler{
  	foobar: "foobar",
  }
  fasthttp.ListenAndServe(":8080", myHandler.HandleFastHTTP)

  // pass plain function to fasthttp
  fasthttp.ListenAndServe(":8081", fastHTTPHandler)
```

## RequestHandler

- The [RequestHandler](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHandler)  
    accepts only one argument - [RequestCtx](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx).
- It contains all the functionality required for http request processing  
    and response writing. Below is an example of a simple request handler conversion  
    from net/http to fasthttp.

```go
  // net/http request handler
  requestHandler := func(w http.ResponseWriter, r *http.Request) {
  	switch r.URL.Path {
  	case "/foo":
  		fooHandler(w, r)
  	case "/bar":
  		barHandler(w, r)
  	default:
  		http.Error(w, "Unsupported path", http.StatusNotFound)
  	}
  }
```

```go
// the corresponding fasthttp request handler
requestHandler := func(ctx *fasthttp.RequestCtx) {
    switch string(ctx.Path()) {
    case "/foo":
        fooHandler(ctx)
    case "/bar":
        barHandler(ctx)
    default:
        ctx.Error("Unsupported path", fasthttp.StatusNotFound)
    }
}
```

## Setting response headers and writing response body

- Fasthttp allows setting response headers and writing response body in an arbitrary order. There is no 'headers first, then body' restriction  like in net/http. 

The following code is valid for fasthttp:    
```go
requestHandler := func(ctx *fasthttp.RequestCtx) {
    // set some headers and status code first
    ctx.SetContentType("foo/bar")
    ctx.SetStatusCode(fasthttp.StatusOK)

    // then write the first part of body
    fmt.Fprintf(ctx, "this is the first part of body\n")

    // then set more headers
    ctx.Response.Header.Set("Foo-Bar", "baz")

    // then write more body
    fmt.Fprintf(ctx, "this is the second part of body\n")

    // then override already written body
    ctx.SetBody([]byte("this is completely new body contents"))

    // then update status code
    ctx.SetStatusCode(fasthttp.StatusNotFound)

    // basically, anything may be updated many times before
    // returning from RequestHandler.
    //
    // Unlike net/http fasthttp doesn't put response to the wire until
    // returning from RequestHandler.
}
 ```
    
## No ServeMux

- Fasthttp doesn't provide [ServeMux](https://pkg.go.dev/net/http#ServeMux),  
    but there are more powerful third-party routers and web frameworks  
    with fasthttp support:
    
    - [fasthttp-routing](https://github.com/qiangxue/fasthttp-routing)
    - [router](https://github.com/fasthttp/router)
    - [lu](https://github.com/vincentLiuxiang/lu)
    - [atreugo](https://github.com/savsgio/atreugo)
    - [Fiber](https://github.com/gofiber/fiber)
    - [Gearbox](https://github.com/gogearbox/gearbox)
	
- Net/http code with simple ServeMux is trivially converted to fasthttp code:
    
```go
// net/http code
m := &http.ServeMux{}  
m.HandleFunc("/foo", fooHandlerFunc)  
m.HandleFunc("/bar", barHandlerFunc)  
m.Handle("/baz", bazHandler)

http.ListenAndServe(":80", m)
```

```go
  // the corresponding fasthttp code
  m := func(ctx *fasthttp.RequestCtx) {
  	switch string(ctx.Path()) {
  	case "/foo":
  		fooHandlerFunc(ctx)
  	case "/bar":
  		barHandlerFunc(ctx)
  	case "/baz":
  		bazHandler.HandlerFunc(ctx)
  	default:
  		ctx.Error("not found", fasthttp.StatusNotFound)
  	}
  }

  fasthttp.ListenAndServe(":80", m)
```

- Because creating a new channel for every request is just too expensive, so the channel returned by RequestCtx.Done() is only closed when the server is shutting down.

```go
func main() {
  fasthttp.ListenAndServe(":8080", fasthttp.TimeoutHandler(func(ctx *fasthttp.RequestCtx) {
  	select {
  	case <-ctx.Done():
  		// ctx.Done() is only closed when the server is shutting down.
  		log.Println("context cancelled")
  		return
  	case <-time.After(10 * time.Second):
  		log.Println("process finished ok")
  	}
  }, time.Second*2, "timeout"))
}
```

## net/http -> fasthttp conversion table:

- All the pseudocode below assumes w, r and ctx have these types:

```go
var (
    w http.ResponseWriter
    r *http.Request
    ctx *fasthttp.RequestCtx
)
```

- r.Body -> [ctx.PostBody()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.PostBody)
- r.URL.Path -> [ctx.Path()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Path)
- r.URL -> [ctx.URI()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.URI)
- r.Method -> [ctx.Method()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Method)
- r.Header -> [ctx.Request.Header](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHeader)
- r.Header.Get() -> [ctx.Request.Header.Peek()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHeader.Peek)
- r.Host -> [ctx.Host()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Host)
- r.Form -> [ctx.QueryArgs()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.QueryArgs) +  
    [ctx.PostArgs()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.PostArgs)
- r.PostForm -> [ctx.PostArgs()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.PostArgs)
- r.FormValue() -> [ctx.FormValue()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.FormValue)
- r.FormFile() -> [ctx.FormFile()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.FormFile)
- r.MultipartForm -> [ctx.MultipartForm()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.MultipartForm)
- r.RemoteAddr -> [ctx.RemoteAddr()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.RemoteAddr)
- r.RequestURI -> [ctx.RequestURI()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.RequestURI)
- r.TLS -> [ctx.IsTLS()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.IsTLS)
- r.Cookie() -> [ctx.Request.Header.Cookie()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHeader.Cookie)
- r.Referer() -> [ctx.Referer()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Referer)
- r.UserAgent() -> [ctx.UserAgent()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.UserAgent)
- w.Header() -> [ctx.Response.Header](https://pkg.go.dev/github.com/valyala/fasthttp#ResponseHeader)
- w.Header().Set() -> [ctx.Response.Header.Set()](https://pkg.go.dev/github.com/valyala/fasthttp#ResponseHeader.Set)
- w.Header().Set("Content-Type") -> [ctx.SetContentType()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.SetContentType)
- w.Header().Set("Set-Cookie") -> [ctx.Response.Header.SetCookie()](https://pkg.go.dev/github.com/valyala/fasthttp#ResponseHeader.SetCookie)
- w.Write() -> [ctx.Write()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Write),  
    [ctx.SetBody()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.SetBody),  
    [ctx.SetBodyStream()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.SetBodyStream),  
    [ctx.SetBodyStreamWriter()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.SetBodyStreamWriter)
- w.WriteHeader() -> [ctx.SetStatusCode()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.SetStatusCode)
- w.(http.Hijacker).Hijack() -> [ctx.Hijack()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Hijack)
- http.Error() -> [ctx.Error()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Error)
- http.FileServer() -> [fasthttp.FSHandler()](https://pkg.go.dev/github.com/valyala/fasthttp#FSHandler),  
    [fasthttp.FS](https://pkg.go.dev/github.com/valyala/fasthttp#FS)
- http.ServeFile() -> [fasthttp.ServeFile()](https://pkg.go.dev/github.com/valyala/fasthttp#ServeFile)
- http.Redirect() -> [ctx.Redirect()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.Redirect)
- http.NotFound() -> [ctx.NotFound()](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.NotFound)
- http.StripPrefix() -> [fasthttp.PathRewriteFunc](https://pkg.go.dev/github.com/valyala/fasthttp#PathRewriteFunc)

**VERY IMPORTANT!**

- Fasthttp disallows holding referencesto [RequestCtx](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx) or to its'  
    members after returning from [RequestHandler](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHandler).  
    Otherwise [data races](http://go.dev/blog/race-detector) are inevitable.
    
- Carefully inspect all the net/http request handlers converted to fasthttp whether  
    they retain references to RequestCtx or to its' members after returning.  
    RequestCtx provides the following *band aids* for this case:
    
- Wrap RequestHandler into [TimeoutHandler](https://pkg.go.dev/github.com/valyala/fasthttp#TimeoutHandler).
    
- Call [TimeoutError](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.TimeoutError) before returning from RequestHandler if there are references to RequestCtx or to its' members.
    
- See [the example](https://pkg.go.dev/github.com/valyala/fasthttp#example-RequestCtx-TimeoutError)  
    for more details.
    
- Use this brilliant tool - [race detector](http://go.dev/blog/race-detector) - for detecting and eliminating data races in your program. If you detected data race related to fasthttp in your program, then there is high probability you forgot calling [TimeoutError](https://pkg.go.dev/github.com/valyala/fasthttp#RequestCtx.TimeoutError) before returning from [RequestHandler](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHandler).
    
- Blind switching from net/http to fasthttp won't give you performance boost.
    
- While fasthttp is optimized for speed, its' performance may be easily saturated by slow [RequestHandler](https://pkg.go.dev/github.com/valyala/fasthttp#RequestHandler).
    
- So [profile](http://go.dev/blog/pprof) and optimize you code after switching to fasthttp.  
    For instance, use [quicktemplate](https://github.com/valyala/quicktemplate) instead of [html/template](https://pkg.go.dev/html/template).
    
- See also [fasthttputil](https://pkg.go.dev/github.com/valyala/fasthttp/fasthttputil),  
    [fasthttpadaptor](https://pkg.go.dev/github.com/valyala/fasthttp/fasthttpadaptor) and  
    [expvarhandler](https://pkg.go.dev/github.com/valyala/fasthttp/expvarhandler).
    

## Performance optimization tips for multi-core systems

- Use [reuseport](https://pkg.go.dev/github.com/valyala/fasthttp/reuseport) listener.
- Run a separate server instance per CPU core with GOMAXPROCS=1.
- Pin each server instance to a separate CPU core using [taskset](http://linux.die.net/man/1/taskset).
- Ensure the interrupts of multiqueue network card are evenly distributed between CPU cores.  
    See [this article](https://blog.cloudflare.com/how-to-achieve-low-latency/) for details.
- Use the latest version of Go as each version contains performance improvements.

## Fasthttp best practices

- Do not allocate objects and `[]byte` buffers - just reuse them as much as possible. Fasthttp API design encourages this.
- [sync.Pool](https://pkg.go.dev/sync#Pool) is your best friend.
- [Profile your program](http://go.dev/blog/pprof) in production.  
    `go tool pprof --alloc_objects your-program mem.pprof` usually gives better  
    insights for optimization opportunities than `go tool pprof your-program cpu.pprof`.
- Write [tests and benchmarks](https://pkg.go.dev/testing) for hot paths.
- Avoid conversion between `[]byte` and `string`, since this may result in memory  
    allocation+copy. Fasthttp API provides functions for both `[]byte` and `string` -  
    use these functions instead of converting manually between `[]byte` and `string`.  
    There are some exceptions - see [this wiki page](https://github.com/golang/go/wiki/CompilerOptimizations#string-and-byte)  
    for more details.
- Verify your tests and production code under  
    [race detector](https://go.dev/doc/articles/race_detector.html) on a regular basis.
- Prefer [quicktemplate](https://github.com/valyala/quicktemplate) instead of  
    [html/template](https://pkg.go.dev/html/template) in your webserver.

## Tricks with `[]byte` buffers

The following tricks are used by fasthttp. Use them in your code too.

- Standard Go functions accept nil buffers

```go
var (
    // both buffers are uninitialized
    dst []byte
    src []byte
)
dst = append(dst, src...)  // is legal if dst is nil and/or src is nil
copy(dst, src)  // is legal if dst is nil and/or src is nil
(string(src) == "")  // is true if src is nil
(len(src) == 0)  // is true if src is nil
src = src[:0]  // works like a charm with nil src

// this for loop doesn't panic if src is nil
for i, ch := range src {
    doSomething(i, ch)
}
```

- So throw away nil checks for `[]byte` buffers from you code. For example,

```go
srcLen := 0
if src != nil {
    srcLen = len(src)
}
```

becomes

```go
srcLen := len(src)
```

- String may be appended to `[]byte` buffer with `append`

```go
dst = append(dst, "foobar"...)
```

- `[]byte` buffer may be extended to its' capacity.

```go
buf := make([]byte, 100)
a := buf[:10]  // len(a) == 10, cap(a) == 100.
b := a[:100]  // is valid, since cap(a) == 100.
```

- All fasthttp functions accept nil `[]byte` buffer

```go
statusCode, body, err := fasthttp.Get(nil, "http://google.com/")
uintBuf := fasthttp.AppendUint(nil, 1234)
```

- String and `[]byte` buffers may converted without memory allocations

```go
func b2s(b []byte) string {
    return *(*string)(unsafe.Pointer(&b))
}

func s2b(s string) (b []byte) {
    bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh.Data = sh.Data
    bh.Cap = sh.Len
    bh.Len = sh.Len
    return b
}
```

### Warning:

- This is an **unsafe** way, the result string and `[]byte` buffer share the same bytes.

**Please make sure not to modify the bytes in the `[]byte` buffer if the string still survives!**

- Make sure there are no references to RequestCtx or to its' members after returning from RequestHandler.
- Make sure you call TimeoutError before returning from RequestHandler if there are references to RequestCtx or to its' members, which may be accessed by other goroutines.