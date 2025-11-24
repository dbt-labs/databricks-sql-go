package u2m

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	tokenCacheFileName   = "databricks_oauth_token_cache.json"
	leaseTTL             = 30 * time.Second
	leaseTimeout         = 90 * time.Second
	cachefilePermissions = 0600

	// Jitter parameters for avoiding thundering herd
	minRetryInterval = 200 * time.Millisecond
	maxRetryInterval = 2 * time.Second
)

// tokenCacheEntry represents a cached OAuth token
type tokenCacheEntry struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
}

// tokenCache handles reading/writing OAuth tokens to disk
type tokenCache struct {
	cacheDir     string
	leaseHandler *LeaseHandler

	// In-memory cache to avoid file reads on every token access
	mu       sync.RWMutex
	memCache map[string]*oauth2.Token // hostname -> token
}

// getCacheDir returns the directory for token cache files
func getCacheDir() (string, error) {
	var dirs []string

	if runtime.GOOS == "windows" {
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			dirs = append(dirs, filepath.Join(appData, "databricks", "oauth"))
		}
	} else {
		// Linux/Mac
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			dirs = append(dirs, filepath.Join(xdgCache, "databricks", "oauth"))
		}
		if home := os.Getenv("HOME"); home != "" {
			dirs = append(dirs, filepath.Join(home, ".cache", "databricks", "oauth"))
		}
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir, nil
		}
	}

	return "", fmt.Errorf("unable to create cache directory")
}

// newTokenCache creates a new token cache
func newTokenCache() (*tokenCache, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	leasePath := filepath.Join(cacheDir, "oauth_flow.lease")
	leaseHandler, err := NewLeaseHandler(leasePath, leaseTimeout)
	if err != nil {
		return nil, err
	}

	return &tokenCache{
		cacheDir:     cacheDir,
		leaseHandler: leaseHandler,
		memCache:     make(map[string]*oauth2.Token),
	}, nil
}

// getCacheFilePath returns the path to the token cache file for a given hostname
func (tc *tokenCache) getCacheFilePath(hostname string) string {
	// Use hostname as part of filename to isolate different Databricks workspaces
	return filepath.Join(tc.cacheDir, fmt.Sprintf("%s_%s", hostname, tokenCacheFileName))
}

// readToken reads a cached token, first from memory, then from disk
func (tc *tokenCache) readToken(hostname string) (*oauth2.Token, error) {
	// Fast path: check in-memory cache first (no lock needed for reads)
	tc.mu.RLock()
	if cached, ok := tc.memCache[hostname]; ok && cached.Valid() {
		tc.mu.RUnlock()
		return cached, nil
	}
	tc.mu.RUnlock()

	// Slow path: read from disk
	token, err := tc.readTokenFromDisk(hostname)
	if err != nil {
		return nil, err
	}

	// Cache in memory for future reads
	if token != nil && token.Valid() {
		tc.mu.Lock()
		tc.memCache[hostname] = token
		tc.mu.Unlock()
	}

	return token, nil
}

// readTokenFromDisk reads a token from the disk cache file
func (tc *tokenCache) readTokenFromDisk(hostname string) (*oauth2.Token, error) {
	path := tc.getCacheFilePath(hostname)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cached token
		}
		return nil, err
	}

	var entry tokenCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken:  entry.AccessToken,
		RefreshToken: entry.RefreshToken,
		TokenType:    entry.TokenType,
		Expiry:       entry.Expiry,
	}

	// Check if token is expired
	if token.Valid() {
		return token, nil
	}

	return nil, nil // Token expired
}

// writeToken writes a token to the cache file and in-memory cache
func (tc *tokenCache) writeToken(hostname string, token *oauth2.Token) error {
	path := tc.getCacheFilePath(hostname)

	entry := tokenCacheEntry{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, cachefilePermissions); err != nil {
		return err
	}

	// Update in-memory cache
	tc.mu.Lock()
	tc.memCache[hostname] = token
	tc.mu.Unlock()

	return nil
}

// acquireLease acquires the OAuth flow lease
func (tc *tokenCache) acquireLease() (*Lease, error) {
	return tc.leaseHandler.Acquire(leaseTTL)
}

// tryAcquireLease attempts to acquire the lease without waiting
func (tc *tokenCache) tryAcquireLease() (*Lease, bool) {
	// Set a very short timeout for non-blocking attempt
	oldTimeout := tc.leaseHandler.getTimeout()
	tc.leaseHandler.SetTimeout(100 * time.Millisecond)
	defer tc.leaseHandler.SetTimeout(oldTimeout)

	lease, err := tc.leaseHandler.Acquire(leaseTTL)
	if err != nil {
		return nil, false
	}
	return lease, true
}
