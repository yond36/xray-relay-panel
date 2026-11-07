package coreversion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const officialReleases = "https://api.github.com/repos/XTLS/Xray-core/releases"
const pageSize = 50
const maxPages = 2
const maxResponseBytes = 8 << 20

type Release struct {
	Tag         string    `json:"tag"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	HTMLURL     string    `json:"html_url"`
}
type ReleaseList struct {
	Releases  []Release `json:"releases"`
	FetchedAt time.Time `json:"fetched_at"`
	Stale     bool      `json:"stale"`
	Error     string    `json:"error,omitempty"`
	Source    string    `json:"source"`
}
type Catalog struct {
	mu            sync.Mutex
	client        *http.Client
	source        string
	clock         func() time.Time
	ttl           time.Duration
	forceInterval time.Duration
	cache         ReleaseList
	etag          string
	lastAttempt   time.Time
	retryAfter    time.Time
	lastError     string
	inflight      chan struct{}
}

func NewCatalog() *Catalog {
	return &Catalog{source: officialReleases, clock: time.Now, ttl: 15 * time.Minute, forceInterval: 5 * time.Minute, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" || req.URL.Hostname() != "api.github.com" {
			return errors.New("官方版本接口重定向地址不被允许")
		}
		return nil
	}}}
}
func cloneList(value ReleaseList) ReleaseList {
	value.Releases = append([]Release{}, value.Releases...)
	return value
}
func (c *Catalog) currentLocked() ReleaseList {
	result := cloneList(c.cache)
	result.Source = officialReleases
	if c.lastError != "" {
		result.Error = c.lastError
		result.Stale = true
	}
	return result
}
func (c *Catalog) List(ctx context.Context, force bool) (ReleaseList, error) {
	for {
		c.mu.Lock()
		now := c.clock()
		hasCache := !c.cache.FetchedAt.IsZero()
		fresh := hasCache && now.Sub(c.cache.FetchedAt) < c.ttl
		cooling := !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < c.forceInterval
		backoff := now.Before(c.retryAfter)
		if fresh && !force || hasCache && (cooling || backoff) {
			out := c.currentLocked()
			c.mu.Unlock()
			return out, nil
		}
		if backoff && !hasCache {
			out := c.currentLocked()
			err := errors.New(c.lastError)
			c.mu.Unlock()
			return out, err
		}
		if waiting := c.inflight; waiting != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ReleaseList{Releases: []Release{}, Source: officialReleases}, ctx.Err()
			case <-waiting:
				force = false
				continue
			}
		}
		c.inflight = make(chan struct{})
		c.lastAttempt = now
		old := cloneList(c.cache)
		etag := c.etag
		c.mu.Unlock()
		fetched, nextETag, notModified, err := c.fetch(ctx, etag)
		c.mu.Lock()
		if err == nil {
			if notModified {
				if old.FetchedAt.IsZero() {
					err = errors.New("官方版本接口返回空缓存的 304 响应")
				} else {
					fetched = old
				}
			}
			if err == nil {
				fetched.FetchedAt = c.clock().UTC()
				fetched.Source = officialReleases
				fetched.Stale = false
				fetched.Error = ""
				c.cache = cloneList(fetched)
				if nextETag != "" {
					c.etag = nextETag
				}
				c.lastError = ""
				c.retryAfter = time.Time{}
			}
		}
		if err != nil {
			// Keep the newest versions available if only an older release page failed.
			if c.cache.FetchedAt.IsZero() && len(fetched.Releases) > 0 {
				fetched.FetchedAt = c.clock().UTC()
				fetched.Source = officialReleases
				c.cache = cloneList(fetched)
			}
			c.lastError = err.Error()
			c.retryAfter = c.clock().Add(time.Minute)
		}
		out := c.currentLocked()
		hasCache = !c.cache.FetchedAt.IsZero()
		close(c.inflight)
		c.inflight = nil
		c.mu.Unlock()
		if err != nil && !hasCache {
			return out, err
		}
		return out, nil
	}
}

type githubRelease struct {
	Tag         string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
}

func (c *Catalog) fetch(ctx context.Context, etag string) (ReleaseList, string, bool, error) {
	out := ReleaseList{Releases: []Release{}, Source: officialReleases}
	nextETag := ""
	seen := map[string]bool{}
	for page := 1; page <= maxPages; page++ {
		address, err := url.Parse(c.source)
		if err != nil {
			return out, "", false, err
		}
		query := address.Query()
		query.Set("per_page", strconv.Itoa(pageSize))
		query.Set("page", strconv.Itoa(page))
		address.RawQuery = query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
		if err != nil {
			return out, "", false, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "Xray-Relay-Panel")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if page == 1 && etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return out, "", false, fmt.Errorf("获取官方核心版本失败：%w", err)
		}
		if page == 1 && resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			return out, resp.Header.Get("ETag"), true, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if resp.StatusCode == 403 || resp.StatusCode == 429 {
				return out, "", false, errors.New("GitHub 官方版本接口暂时限流，请稍后刷新或输入自定义版本")
			}
			return out, "", false, fmt.Errorf("官方版本接口返回 HTTP %d，可使用自定义版本", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			return out, "", false, fmt.Errorf("读取官方版本列表失败：%w", err)
		}
		if len(data) > maxResponseBytes {
			return out, "", false, errors.New("官方版本列表响应超过大小限制")
		}
		if page == 1 {
			nextETag = resp.Header.Get("ETag")
		}
		var values []githubRelease
		if err = json.Unmarshal(data, &values); err != nil {
			return out, "", false, errors.New("官方版本接口返回了无效 JSON")
		}
		if len(values) > pageSize {
			return out, "", false, errors.New("官方版本接口返回的版本数量不合法")
		}
		for _, value := range values {
			tag, err := Normalize(value.Tag)
			if err != nil || value.Draft || seen[tag] {
				continue
			}
			seen[tag] = true
			name := strings.TrimSpace(value.Name)
			if name == "" {
				name = tag
			}
			runes := []rune(name)
			if len(runes) > 200 {
				name = string(runes[:200])
			}
			out.Releases = append(out.Releases, Release{Tag: tag, Name: name, PublishedAt: value.PublishedAt, Prerelease: value.Prerelease, HTMLURL: "https://github.com/XTLS/Xray-core/releases/tag/" + url.PathEscape(tag)})
		}
		if len(values) < pageSize {
			break
		}
	}
	if len(out.Releases) == 0 {
		return out, "", false, errors.New("官方版本接口没有返回可选择的版本，可输入自定义版本")
	}
	return out, nextETag, false, nil
}
