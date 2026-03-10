package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pdns api %s %s failed with status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	mu      sync.RWMutex
}

func NewClient(config Config) *Client {
	return &Client{
		baseURL: config.BaseURL,
		apiKey:  config.APIKey,
		http: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	return c.request(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body interface{}, out interface{}) error {
	return c.request(ctx, http.MethodPost, path, body, out)
}

func (c *Client) patch(ctx context.Context, path string, body interface{}, out interface{}) error {
	return c.request(ctx, http.MethodPatch, path, body, out)
}

func (c *Client) put(ctx context.Context, path string, body interface{}, out interface{}) error {
	return c.request(ctx, http.MethodPut, path, body, out)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) request(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	path = "/" + strings.TrimLeft(path, "/")
	var payload []byte
	if body != nil {
		marshaled, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return fmt.Errorf("marshal request body: %w", marshalErr)
		}
		payload = marshaled
	}

	baseURL := c.getBaseURL()
	err := c.requestOnce(ctx, baseURL, method, path, payload, out)
	if err == nil {
		return nil
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || !shouldRetryWithAPIV1(path, apiErr.Status) {
		return err
	}

	retryBaseURL, ok := withAPIV1Suffix(baseURL)
	if !ok || retryBaseURL == baseURL {
		return err
	}

	retryErr := c.requestOnce(ctx, retryBaseURL, method, path, payload, out)
	if retryErr != nil {
		return retryErr
	}

	c.setBaseURL(retryBaseURL)
	return nil
}

func (c *Client) requestOnce(ctx context.Context, baseURL, method, path string, payload []byte, out interface{}) error {
	endpoint, err := url.JoinPath(baseURL, path)
	if err != nil {
		return fmt.Errorf("build url: %w", err)
	}

	var requestBody io.Reader
	if len(payload) > 0 {
		requestBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(rawBody))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return &APIError{
			Method: method,
			Path:   path,
			Status: resp.StatusCode,
			Body:   msg,
		}
	}

	if out == nil || len(rawBody) == 0 {
		return nil
	}

	if err := json.Unmarshal(rawBody, out); err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}

	return nil
}

func (c *Client) getBaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL
}

func (c *Client) setBaseURL(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = baseURL
}

func shouldRetryWithAPIV1(path string, status int) bool {
	if status != http.StatusNotFound {
		return false
	}

	normalized := "/" + strings.TrimLeft(strings.TrimSpace(path), "/")
	return normalized == "/servers" || strings.HasPrefix(normalized, "/servers/")
}

func withAPIV1Suffix(baseURL string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", false
	}

	trimmedPath := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(trimmedPath, "/api/v1") {
		return strings.TrimRight(parsed.String(), "/"), false
	}

	if trimmedPath == "" {
		parsed.Path = "/api/v1"
	} else {
		parsed.Path = trimmedPath + "/api/v1"
	}

	return strings.TrimRight(parsed.String(), "/"), true
}
