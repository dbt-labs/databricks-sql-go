package u2m

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// mockTokenSource is a test token source that returns a fixed token
type mockTokenSource struct {
	token *oauth2.Token
	err   error
	calls int
	mu    sync.Mutex
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

func (m *mockTokenSource) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// mockTokenSourceProvider simulates the token source provider for testing.
// It allows controlled timing and behavior for concurrency testing.
type mockTokenSourceProvider struct {
	tokenSource oauth2.TokenSource
	err         error
	delay       time.Duration
	calls       int
	mu          sync.Mutex

	// For tracking concurrent access
	activeCallsCount   int
	maxConcurrentCalls int
}

func (m *mockTokenSourceProvider) GetTokenSource(optionalLease *Lease) (oauth2.TokenSource, error) {
	m.mu.Lock()
	m.calls++
	m.activeCallsCount++
	if m.activeCallsCount > m.maxConcurrentCalls {
		m.maxConcurrentCalls = m.activeCallsCount
	}
	delay := m.delay
	m.mu.Unlock()

	// Simulate the time it takes to complete OAuth flow
	if delay > 0 {
		time.Sleep(delay)
	}

	m.mu.Lock()
	m.activeCallsCount--
	tokenSource := m.tokenSource
	err := m.err
	m.mu.Unlock()

	return tokenSource, err
}

func (m *mockTokenSourceProvider) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *mockTokenSourceProvider) MaxConcurrentCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maxConcurrentCalls
}

// mockHTTPHandler simulates the OAuth provider's token endpoint
type mockHTTPHandler struct {
	tokenResponses []string
	callCount      int
	mu             sync.Mutex
}

func (m *mockHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if r.URL.Path == "/token" {
		w.Header().Set("Content-Type", "application/json")
		if m.callCount <= len(m.tokenResponses) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(m.tokenResponses[m.callCount-1]))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "unexpected call"}`))
		}
	}
}

func TestU2MAuthenticator_Authenticate(t *testing.T) {
	t.Run("should authenticate with valid token", func(t *testing.T) {
		mockToken := &oauth2.Token{
			AccessToken: "valid_token_123",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: mockTS,
		}

		req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
		err := auth.Authenticate(req)

		assert.Nil(t, err)
		assert.Equal(t, "Bearer valid_token_123", req.Header.Get("Authorization"))
		assert.Equal(t, 1, mockTS.CallCount())
	})

	t.Run("should reuse valid token on multiple calls", func(t *testing.T) {
		mockToken := &oauth2.Token{
			AccessToken: "reusable_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: mockTS,
		}

		// Make multiple authentication calls
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
			err := auth.Authenticate(req)
			assert.Nil(t, err)
			assert.Equal(t, "Bearer reusable_token", req.Header.Get("Authorization"))
		}

		// Token() is called on every Authenticate() - no caching at this level
		assert.Equal(t, 5, mockTS.CallCount())
	})

	t.Run("should return error when token fetch fails", func(t *testing.T) {
		mockTS := &mockTokenSource{
			err: fmt.Errorf("token fetch failed"),
		}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: mockTS,
		}

		req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
		err := auth.Authenticate(req)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "token fetch failed")
	})
}

func TestU2MAuthenticator_RetryInitOnTokenError(t *testing.T) {
	// Initial token source fails
	failingTS := &mockTokenSource{err: fmt.Errorf("initial token error")}

	// Provider returns a working token source on re-init
	goodToken := &oauth2.Token{AccessToken: "new_token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
	goodTS := &mockTokenSource{token: goodToken}
	provider := &mockTokenSourceProvider{tokenSource: goodTS}

	auth := &u2mAuthenticator{
		clientID:    "test-client",
		hostName:    "h",
		tokenSource: failingTS,
		tsp:         provider,
	}

	req := httptest.NewRequest("GET", "http://h/api", nil)
	err := auth.Authenticate(req)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer new_token", req.Header.Get("Authorization"))
	assert.Equal(t, 1, provider.CallCount())
}

func TestU2MAuthenticator_PersistsTokenToCache(t *testing.T) {
	tmp := t.TempDir()

	// Build a token cache bound to temp dir
	leasePath := filepath.Join(tmp, "lease")
	lh, err := NewLeaseHandler(leasePath, leaseTimeout)
	assert.NoError(t, err)
	tc := &tokenCache{cacheDir: tmp, leaseHandler: lh, memCache: make(map[string]*oauth2.Token)}

	// Provider instance carrying the token cache
	tsp := &tokenSourceProvider{
		timeout:     500 * time.Millisecond,
		sigintCh:    make(chan os.Signal, 1),
		authDoneCh:  make(chan authResponse),
		redirectURL: &url.URL{Scheme: "http", Host: "localhost:8039", Path: "/"},
		tokenCache:  tc,
		hostname:    "workspace-1",
	}

	tok := &oauth2.Token{AccessToken: "persist_me", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
	ts := &mockTokenSource{token: tok}

	auth := &u2mAuthenticator{clientID: "c", hostName: "workspace-1", tokenSource: ts, tsp: tsp}

	req := httptest.NewRequest("GET", "http://workspace-1/api", nil)
	err = auth.Authenticate(req)
	assert.NoError(t, err)

	// Verify token written to cache file
	path := tc.getCacheFilePath("workspace-1")
	data, readErr := os.ReadFile(path)
	assert.NoError(t, readErr)
	assert.Contains(t, string(data), "persist_me")
}

func TestU2MAuthenticator_ConcurrentAuthentication(t *testing.T) {
	t.Run("should handle concurrent authentication requests", func(t *testing.T) {
		mockToken := &oauth2.Token{
			AccessToken: "concurrent_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: mockTS,
		}

		// Launch multiple goroutines that authenticate simultaneously
		const numGoroutines = 10
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
				errors[idx] = auth.Authenticate(req)
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i, err := range errors {
			assert.Nil(t, err, fmt.Sprintf("goroutine %d failed", i))
		}

		// Each Authenticate() calls Token() - no caching optimization
		assert.Equal(t, 10, mockTS.CallCount())
	})

	t.Run("should expose cross-process safety issues", func(t *testing.T) {
		// This test documents that the current implementation
		// is NOT safe across multiple processes because:
		// 1. The mutex only protects within a single process
		// 2. Multiple processes would each start their own HTTP servers
		// 3. Port conflicts would occur when both try to bind to same port
		// 4. No shared state management (file locks, distributed locks) exists
		// 5. The sync.Once register is per-process, not system-wide

		// Simulate two separate authenticator instances (like in different processes)
		tsp1 := &tokenSourceProvider{
			timeout:     1 * time.Second,
			sigintCh:    make(chan os.Signal, 1),
			authDoneCh:  make(chan authResponse),
			redirectURL: &url.URL{Scheme: "http", Host: "localhost:8030", Path: "/"},
			config: oauth2.Config{
				ClientID:    "test-client-1",
				RedirectURL: "http://localhost:8030",
			},
		}

		tsp2 := &tokenSourceProvider{
			timeout:     1 * time.Second,
			sigintCh:    make(chan os.Signal, 1),
			authDoneCh:  make(chan authResponse),
			redirectURL: &url.URL{Scheme: "http", Host: "localhost:8030", Path: "/"},
			config: oauth2.Config{
				ClientID:    "test-client-2",
				RedirectURL: "http://localhost:8030",
			},
		}

		// Verify separate instances (simulating different processes)
		assert.NotEqual(t, fmt.Sprintf("%p", tsp1), fmt.Sprintf("%p", tsp2))
		assert.Equal(t, "localhost:8030", tsp1.redirectURL.Host)
		assert.Equal(t, "localhost:8030", tsp2.redirectURL.Host)
	})
}

func TestTokenSourceProvider_GetTokenSource(t *testing.T) {
	t.Run("should timeout when no callback received", func(t *testing.T) {
		// Create a mock server for the OAuth provider
		mockHandler := &mockHTTPHandler{
			tokenResponses: []string{
				`{"access_token": "test_token", "token_type": "Bearer", "expires_in": 3600}`,
			},
		}
		server := httptest.NewServer(mockHandler)
		defer server.Close()

		config := oauth2.Config{
			ClientID:    "test-client",
			Endpoint:    oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"},
			RedirectURL: "http://localhost:8031",
		}

		tsp := &tokenSourceProvider{
			timeout:     100 * time.Millisecond, // Short timeout for testing
			sigintCh:    make(chan os.Signal, 1),
			authDoneCh:  make(chan authResponse),
			redirectURL: &url.URL{Scheme: "http", Host: "localhost:8031", Path: "/"},
			config:      config,
		}

		// Call GetTokenSource without sending a callback
		_, err := tsp.GetTokenSource(nil)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "timed out waiting for response")
	})
}

func TestConcurrencyIssues(t *testing.T) {
	t.Run("demonstrates race condition when tokenSource is nil", func(t *testing.T) {
		// This test demonstrates what happens when multiple goroutines
		// try to authenticate simultaneously with no cached token

		mockToken := &oauth2.Token{
			AccessToken: "new_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}

		// Mock provider with a delay to simulate OAuth flow
		mockProvider := &mockTokenSourceProvider{
			tokenSource: mockTS,
			delay:       100 * time.Millisecond, // Simulate OAuth flow taking time
		}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: nil, // Initially nil - this is the key scenario
			tsp:         mockProvider,
		}

		const numGoroutines = 10
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)
		startTime := time.Now()

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
				errors[idx] = auth.Authenticate(req)
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(startTime)

		// All should succeed
		for i, err := range errors {
			assert.Nil(t, err, fmt.Sprintf("goroutine %d failed", i))
		}

		providerCalls := mockProvider.CallCount()
		maxConcurrent := mockProvider.MaxConcurrentCalls()

		// Mutex should ensure only 1 call to GetTokenSource
		assert.Equal(t, 1, providerCalls, "expected single GetTokenSource call")
		assert.Equal(t, 1, maxConcurrent, "expected no concurrent GetTokenSource calls")

		if elapsed > 200*time.Millisecond {
			t.Errorf("concurrent requests took too long: %v (expected ~100ms)", elapsed)
		}
	})

	t.Run("demonstrates behavior with cached token", func(t *testing.T) {
		// This test shows that with a cached token, GetTokenSource should not be called

		mockToken := &oauth2.Token{
			AccessToken: "cached_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}
		mockProvider := &mockTokenSourceProvider{
			tokenSource: mockTS,
			delay:       100 * time.Millisecond,
		}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: mockTS, // Pre-cached token
			tsp:         mockProvider,
		}

		const numGoroutines = 10
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
				errors[idx] = auth.Authenticate(req)
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i, err := range errors {
			assert.Nil(t, err, fmt.Sprintf("goroutine %d failed", i))
		}

		providerCalls := mockProvider.CallCount()
		tokenCalls := mockTS.CallCount()

		assert.Equal(t, 0, providerCalls, "GetTokenSource should not be called with cached token")
		assert.Equal(t, 10, tokenCalls, "Token() called for each authentication")
	})

	t.Run("simulates realistic OAuth flow timing", func(t *testing.T) {
		// This test simulates what happens in production:
		// OAuth flow takes several seconds (browser, user interaction, callback)
		// Multiple requests might come in during this time

		mockToken := &oauth2.Token{
			AccessToken: "oauth_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		mockTS := &mockTokenSource{token: mockToken}
		mockProvider := &mockTokenSourceProvider{
			tokenSource: mockTS,
			delay:       500 * time.Millisecond, // Realistic OAuth flow time
		}

		auth := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: nil,
			tsp:         mockProvider,
		}

		const numGoroutines = 20
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)
		startTimes := make([]time.Time, numGoroutines)
		endTimes := make([]time.Time, numGoroutines)

		startTime := time.Now()

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				startTimes[idx] = time.Now()
				req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
				errors[idx] = auth.Authenticate(req)
				endTimes[idx] = time.Now()
			}(i)
		}

		wg.Wait()
		totalElapsed := time.Since(startTime)

		// Check all succeeded
		for i, err := range errors {
			assert.Nil(t, err, fmt.Sprintf("goroutine %d failed", i))
		}

		providerCalls := mockProvider.CallCount()

		assert.Equal(t, 1, providerCalls, "expected single OAuth flow for all concurrent requests")

		if totalElapsed > 600*time.Millisecond {
			t.Errorf("concurrent authentication took too long: %v", totalElapsed)
		}
	})

	t.Run("demonstrates cross-process safety issues with separate instances", func(t *testing.T) {
		// This test simulates what happens with multiple processes:
		// Each process has its own authenticator instance
		// The mutex only protects within each process

		mockToken := &oauth2.Token{
			AccessToken: "process_token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		}

		// Create two separate authenticators (simulating different processes)
		auth1 := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: nil,
			tsp: &mockTokenSourceProvider{
				tokenSource: &mockTokenSource{token: mockToken},
				delay:       100 * time.Millisecond,
			},
		}

		auth2 := &u2mAuthenticator{
			clientID:    "test-client",
			hostName:    "test.databricks.com",
			tokenSource: nil,
			tsp: &mockTokenSourceProvider{
				tokenSource: &mockTokenSource{token: mockToken},
				delay:       100 * time.Millisecond,
			},
		}

		// Both authenticators try to authenticate simultaneously
		var wg sync.WaitGroup
		errors := make([]error, 2)

		wg.Add(2)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
			errors[0] = auth1.Authenticate(req)
		}()

		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://test.databricks.com/api/test", nil)
			errors[1] = auth2.Authenticate(req)
		}()

		wg.Wait()

		// Both succeed
		assert.Nil(t, errors[0])
		assert.Nil(t, errors[1])

		provider1 := auth1.tsp.(*mockTokenSourceProvider)
		provider2 := auth2.tsp.(*mockTokenSourceProvider)

		// Each process initiates its own OAuth flow - no cross-process coordination
		assert.Equal(t, 1, provider1.CallCount())
		assert.Equal(t, 1, provider2.CallCount())

		t.Log("Note: Separate authenticator instances do not coordinate OAuth flows")
	})
}
