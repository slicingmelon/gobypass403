package rawhttp

import "github.com/valyala/fasthttp"

func (c *HttpClient) SetDialer(dialer fasthttp.DialFunc) *HttpClient {
	if c.client != nil {
		c.client.Dial = dialer
	}
	return c
}
