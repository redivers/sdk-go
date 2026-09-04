package client

import (
	"context"
	"net/http"
	"slices"
	"time"

	"buf.build/gen/go/rediver/api/connectrpc/go/networkscan/networkscanconnect"
	"connectrpc.com/connect"
	"github.com/redivers/sdk-go/internal/contract"
)

// Client owns backend RPCs and the native-to-wire conversion boundary.
type Client struct {
	rpc            networkscanconnect.ScannerServiceClient
	requestTimeout time.Duration
	retryPolicy    contract.RetryPolicy
}

// New captures connection settings without changing the caller's HTTP client.
func New(token, serverURL string, httpClient *http.Client, requestTimeout time.Duration, policy contract.RetryPolicy) *Client {
	interceptor := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, requestTimeout)
			defer cancel()
			req.Header().Set("X-Token", token)
			req.Header().Del("Authorization")
			return next(ctx, req)
		}
	})
	client := *httpClient
	// RPC endpoints are exact; redirects must never forward authentication.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	policy.RetryableStatusCodes = slices.Clone(policy.RetryableStatusCodes)
	return &Client{rpc: networkscanconnect.NewScannerServiceClient(&client, serverURL, connect.WithInterceptors(interceptor)), requestTimeout: requestTimeout, retryPolicy: policy}
}

// retry bounds the whole operation, including backoff and the final attempt.
func (c *Client) retry(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	return retry(c.retryPolicy, ctx, func() error { return fn(ctx) })
}
