package masq

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// CachedPage holds a pre-fetched page response.
type CachedPage struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// StaticCache fetches and stores a real website's pages in memory.
// Pre-fetched on startup so responses are instant even if upstream becomes unreachable.
type StaticCache struct {
	pages map[string]CachedPage
	mu    sync.RWMutex
	root  CachedPage // fallback for unknown paths
}

// NewStaticCacheInMemory creates a StaticCache from provided content without making
// any HTTP requests. Intended for tests and embedded deployments.
func NewStaticCacheInMemory(body []byte) *StaticCache {
	page := CachedPage{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       body,
	}
	c := &StaticCache{pages: make(map[string]CachedPage)}
	for _, p := range []string{"/", "/index.html", "/favicon.ico", "/robots.txt"} {
		c.pages[p] = page
	}
	c.root = page
	return c
}

// NewStaticCache fetches /, /index.html, /favicon.ico from baseURL.
// Returns error if the root fetch fails — server must not start without cache.
func NewStaticCache(baseURL string, timeout time.Duration) (*StaticCache, error) {
	c := &StaticCache{
		pages: make(map[string]CachedPage),
	}

	client := &http.Client{Timeout: timeout}

	paths := []string{"/", "/index.html", "/favicon.ico", "/robots.txt"}
	var rootFetched bool

	for _, p := range paths {
		page, err := fetch(client, baseURL+p)
		if err != nil {
			if p == "/" {
				return nil, fmt.Errorf("cannot fetch masquerade content from %s. Server will not start without masquerade content. Cause: %w", baseURL, err)
			}
			continue
		}
		c.pages[p] = page
		if p == "/" {
			c.root = page
			rootFetched = true
		}
	}

	if !rootFetched {
		return nil, fmt.Errorf("cannot fetch masquerade content from %s. Server will not start without masquerade content", baseURL)
	}

	return c, nil
}

// Handler returns an http.Handler that serves cached pages.
// Unknown paths return the cached / response to mimic a CDN.
func (c *StaticCache) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.RLock()
		page, ok := c.pages[r.URL.Path]
		if !ok {
			page = c.root
		}
		c.mu.RUnlock()

		for k, vv := range page.Headers {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(page.StatusCode)
		w.Write(page.Body) //nolint:errcheck
	})
}

func fetch(client *http.Client, url string) (CachedPage, error) {
	resp, err := client.Get(url)
	if err != nil {
		return CachedPage{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap
	if err != nil {
		return CachedPage{}, err
	}

	// Strip hop-by-hop headers not suitable for caching
	h := resp.Header.Clone()
	for _, hdr := range []string{"Transfer-Encoding", "Connection", "Keep-Alive", "Upgrade"} {
		h.Del(hdr)
	}

	return CachedPage{
		StatusCode: resp.StatusCode,
		Headers:    h,
		Body:       body,
	}, nil
}
