package matcher

import (
	"net"
	"net/http"
	"time"
)

var sharedHTTPTransport = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     90 * time.Second,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
}

// sharedHTTPClient is the default HTTP client shared by most matchers.
// It provides optimised connection pooling and timeouts.
var sharedHTTPClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: sharedHTTPTransport,
}
