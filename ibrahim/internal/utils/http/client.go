package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ClientOptions contains options for creating a new HTTP client
type ClientOptions struct {
	// Timeout is the timeout for requests
	Timeout time.Duration

	// UserAgent is the User-Agent header to use
	UserAgent string

	// Proxy is the proxy URL to use
	Proxy string

	// SkipTLSVerify skips TLS certificate verification
	SkipTLSVerify bool

	// Headers are additional headers to include in requests
	Headers map[string]string

	// Cookies are cookies to include in requests
	Cookies []*http.Cookie
}

// Client is a wrapper around http.Client with additional functionality
type Client struct {
	*http.Client
	options *ClientOptions
}

// NewClient creates a new HTTP client
func NewClient(options *ClientOptions) (*Client, error) {
	if options == nil {
		options = &ClientOptions{
			Timeout:   30 * time.Second,
			UserAgent: "SpiderJS/1.0.0",
		}
	}

	// Set default timeout if not specified
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}

	// Set default user agent if not specified
	if options.UserAgent == "" {
		options.UserAgent = "SpiderJS/1.0.0"
	}

	// Create transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: options.SkipTLSVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set proxy if specified
	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Create client
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
	}

	return &Client{
		Client:  client,
		options: options,
	}, nil
}

// Get sends a GET request
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

// Post sends a POST request with the specified content type and body
func (c *Client) Post(ctx context.Context, url string, contentType string, body []byte) (*http.Response, error) {
	bodyReader := bytes.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Do sends an HTTP request and returns an HTTP response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Add headers
	req.Header.Set("User-Agent", c.options.UserAgent)

	for key, value := range c.options.Headers {
		req.Header.Set(key, value)
	}

	// Add cookies
	for _, cookie := range c.options.Cookies {
		req.AddCookie(cookie)
	}

	// Send request
	return c.Client.Do(req)
}

// SetTimeout sets the timeout for requests
func (c *Client) SetTimeout(timeout time.Duration) {
	c.options.Timeout = timeout
	c.Client.Timeout = timeout
}

// SetUserAgent sets the User-Agent header
func (c *Client) SetUserAgent(userAgent string) {
	c.options.UserAgent = userAgent
}

// SetProxy sets the proxy URL
func (c *Client) SetProxy(proxy string) error {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	c.options.Proxy = proxy

	transport, ok := c.Client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("client transport is not an *http.Transport")
	}

	transport.Proxy = http.ProxyURL(proxyURL)

	return nil
}

// SetSkipTLSVerify sets whether to skip TLS certificate verification
func (c *Client) SetSkipTLSVerify(skip bool) {
	c.options.SkipTLSVerify = skip

	transport, ok := c.Client.Transport.(*http.Transport)
	if !ok {
		return
	}

	transport.TLSClientConfig.InsecureSkipVerify = skip
}

// AddHeader adds a header to requests
func (c *Client) AddHeader(key, value string) {
	if c.options.Headers == nil {
		c.options.Headers = make(map[string]string)
	}

	c.options.Headers[key] = value
}

// AddCookie adds a cookie to requests
func (c *Client) AddCookie(cookie *http.Cookie) {
	c.options.Cookies = append(c.options.Cookies, cookie)
}
