package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HTTPBanner contains information gathered from an HTTP probe.
type HTTPBanner struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	StatusCode   int    `json:"status_code"`
	ServerHeader string `json:"server_header,omitempty"`
	Title        string `json:"title,omitempty"`
	BodySnippet  string `json:"body_snippet,omitempty"`
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// HTTPProbe probes a single host:port for HTTP banners.
func HTTPProbe(ip string, port int) (*HTTPBanner, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	banner := &HTTPBanner{
		IP:           ip,
		Port:         port,
		StatusCode:   resp.StatusCode,
		ServerHeader: resp.Header.Get("Server"),
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err == nil && len(body) > 0 {
		matches := titleRe.FindSubmatch(body)
		if len(matches) >= 2 {
			banner.Title = strings.TrimSpace(string(matches[1]))
		}
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		banner.BodySnippet = snippet
	}

	return banner, nil
}

// HTTPProbeBatch probes multiple hosts for HTTP banners concurrently.
func HTTPProbeBatch(hosts []Host) []HTTPBanner {
	httpPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true}

	var candidates []Host
	for _, h := range hosts {
		if httpPorts[h.Port] {
			candidates = append(candidates, h)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	var mu sync.Mutex
	var results []HTTPBanner
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for _, h := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(host Host) {
			defer wg.Done()
			defer func() { <-sem }()

			banner, err := HTTPProbe(host.IP, host.Port)
			if err != nil {
				return
			}
			mu.Lock()
			results = append(results, *banner)
			mu.Unlock()
		}(h)
	}

	wg.Wait()
	return results
}
