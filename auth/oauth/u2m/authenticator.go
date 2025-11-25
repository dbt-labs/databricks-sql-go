package u2m

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/pkg/browser"

	"github.com/databricks/databricks-sql-go/auth"
	"github.com/databricks/databricks-sql-go/auth/oauth"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	azureClientId = "96eecda7-19ea-49cc-abb5-240097d554f5"

	awsClientId = "databricks-sql-connector"

	gcpClientId = "databricks-sql-connector"

	defaultPort = 8030
)

// NewAuthenticator creates a new U2M OAuth authenticator.
// The port parameter specifies the local port for the OAuth redirect callback.
// If port is 0, the default port (8030) will be used.
// Example DSN usage: "https://host?authType=databricks-oauth&oauthRedirectPort=9000"
func NewAuthenticator(hostName string, timeout time.Duration, port int) (auth.Authenticator, error) {

	cloud := oauth.InferCloudFromHost(hostName)

	var clientID string
	if cloud == oauth.AWS {
		clientID = awsClientId
	} else if cloud == oauth.Azure {
		clientID = azureClientId
	} else if cloud == oauth.GCP {
		clientID = gcpClientId
	} else {
		return nil, errors.New("unhandled cloud type: " + cloud.String())
	}

	// Use default port if not specified
	if port == 0 {
		port = defaultPort
	}

	redirectURL := fmt.Sprintf("localhost:%d", port)

	// Get an oauth2 config
	config, err := GetConfig(context.Background(), hostName, clientID, "", redirectURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to generate oauth2.Config: %w", err)
	}

	// Initialize token cache for cross-process coordination
	tokenCache, err := newTokenCache()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize token cache: %w", err)
	}

	tsp, err := GetTokenSourceProvider(context.Background(), config, timeout, tokenCache, hostName)

	return &u2mAuthenticator{
		clientID: clientID,
		hostName: hostName,
		tsp:      tsp,
	}, err
}

type u2mAuthenticator struct {
	clientID string
	hostName string
	// scopes      []string
	tokenSource oauth2.TokenSource
	tokenError  error // Cached GetTokenSource error
	tsp         tokenSourceProviderInterface
	mx          sync.Mutex
}

// Auth will start the OAuth Authorization Flow to authenticate the cli client
// using the users credentials in the browser. Compatible with SSO.
func (c *u2mAuthenticator) Authenticate(r *http.Request) error {
	c.mx.Lock()
	defer c.mx.Unlock()

	// Lazy init or re-init token source if needed
	if c.tokenSource == nil {
		ts, err := c.tsp.GetTokenSource()
		if err != nil {
			c.tokenError = err
			return fmt.Errorf("unable to get token source: %w", err)
		}
		c.tokenSource = ts
		c.tokenError = nil
	}

	// Attempt to get token; on failure, try one re-init
	token, err := c.tokenSource.Token()
	if err != nil {
		// Clear and retry once
		c.tokenSource = nil
		ts, err2 := c.tsp.GetTokenSource()
		if err2 != nil {
			return err
		}
		c.tokenSource = ts
		token, err = c.tokenSource.Token()
		if err != nil {
			return err
		}
	}

	token.SetAuthHeader(r)

	// Persist token to cache
	if tspImpl, ok := c.tsp.(*tokenSourceProvider); ok && tspImpl.tokenCache != nil {
		_ = tspImpl.tokenCache.writeToken(c.hostName, token)
	}
	return nil
}

type authResponse struct {
	err     string
	details string
	state   string
	code    string
}

type tokenSourceProviderInterface interface {
	GetTokenSource() (oauth2.TokenSource, error)
}

type tokenSourceProvider struct {
	timeout     time.Duration
	state       string
	sigintCh    chan os.Signal
	authDoneCh  chan authResponse
	redirectURL *url.URL
	config      oauth2.Config
	tokenCache  *tokenCache
	hostname    string
}

func (tsp *tokenSourceProvider) GetTokenSource() (oauth2.TokenSource, error) {
	ctx := context.Background()

	// Step 1: Try to read cached token first
	if token, err := tsp.tokenCache.readToken(tsp.hostname); err == nil && token != nil {
		log.Info().Msg("Using cached OAuth token")
		return tsp.config.TokenSource(ctx, token), nil
	}

	// Step 2: Try to acquire lease to perform OAuth flow
	lease, acquired := tsp.tokenCache.tryAcquireLease()

	if acquired {
		// We got the lease - perform OAuth flow
		defer lease.Release()
		log.Info().Msg("Acquired OAuth flow lease, starting browser authentication")

		tokenSource, err := tsp.performOAuthFlow()
		if err != nil {
			return nil, err
		}

		// Cache the token for other processes
		if token, err := tokenSource.Token(); err == nil {
			if err := tsp.tokenCache.writeToken(tsp.hostname, token); err != nil {
				log.Warn().Err(err).Msg("Failed to cache OAuth token")
			} else {
				log.Info().Msg("OAuth token cached successfully")
			}
		}

		return tokenSource, nil
	}

	// Step 3: Someone else has the lease - wait for them to complete OAuth and cache the token
	log.Info().Msg("Another process is performing OAuth authentication, waiting for cached token...")

	// Use exponential backoff with jitter to avoid thundering herd
	baseInterval := minRetryInterval
	maxInterval := maxRetryInterval
	deadline := time.Now().Add(tsp.timeout)

	for time.Now().Before(deadline) {
		// Wait with jitter: random interval between baseInterval and maxInterval
		jitter := time.Duration(mathrand.Int63n(int64(maxInterval-baseInterval))) + baseInterval
		remaining := deadline.Sub(time.Now())
		if jitter > remaining {
			jitter = remaining
		}
		time.Sleep(jitter)

		if token, err := tsp.tokenCache.readToken(tsp.hostname); err == nil && token != nil {
			log.Info().Msg("OAuth token cached by another process, using it")
			return tsp.config.TokenSource(ctx, token), nil
		}

		// Exponential backoff for next iteration
		baseInterval = maxInterval / 2
		maxInterval = min(maxInterval*2, 10*time.Second)
	}

	return nil, errors.New("timed out waiting for OAuth token from another process")
}

// performOAuthFlow executes the actual OAuth browser flow
func (tsp *tokenSourceProvider) performOAuthFlow() (oauth2.TokenSource, error) {
	state, err := randString(16)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random number: %w", err)
	}

	challenge, challengeMethod, verifier, err := GetAuthCodeOptions()
	if err != nil {
		return nil, err
	}

	loginURL := tsp.config.AuthCodeURL(state, challenge, challengeMethod)
	tsp.state = state

	log.Info().Msgf("listening on %s://%s/", tsp.redirectURL.Scheme, tsp.redirectURL.Host)
	listener, err := net.Listen("tcp", tsp.redirectURL.Host)
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	// Create a dedicated mux for this server (not global DefaultServeMux)
	mux := http.NewServeMux()
	mux.Handle(tsp.redirectURL.Path, tsp)

	srv := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      30 * time.Second,
		Handler:           mux,
	}

	defer srv.Close()

	// Start local server to wait for callback
	go func() {
		err := srv.Serve(listener)

		// in case port is in use
		if err != nil && err != http.ErrServerClosed {
			tsp.authDoneCh <- authResponse{err: err.Error()}
		}
	}()

	fmt.Printf("\nOpen URL in Browser to Continue: %s\n\n", loginURL)
	err = browser.OpenURL(loginURL)
	if err != nil {
		fmt.Println("Unable to open browser automatically. Please open manually: ", loginURL)
	}

	ctx := context.Background()
	// Wait for callback to be received, Wait for either the callback to finish, SIGINT to be received or up to 2 minutes
	select {
	case authResponse := <-tsp.authDoneCh:
		if authResponse.err != "" {
			return nil, fmt.Errorf("identity provider error: %s: %s", authResponse.err, authResponse.details)
		}
		token, err := tsp.config.Exchange(ctx, authResponse.code, verifier)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange token: %w", err)
		}

		return tsp.config.TokenSource(ctx, token), nil

	case <-tsp.sigintCh:
		return nil, errors.New("interrupted while waiting for auth callback")

	case <-time.After(tsp.timeout):
		return nil, errors.New("timed out waiting for response from provider")
	}
}

func (tsp *tokenSourceProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/favicon.ico" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	resp := authResponse{
		err:     r.URL.Query().Get("error"),
		details: r.URL.Query().Get("error_description"),
		state:   r.URL.Query().Get("state"),
		code:    r.URL.Query().Get("code"),
	}

	// Ignore empty requests (could be pre-flight, etc.)
	if resp.state == "" && resp.code == "" && resp.err == "" {
		log.Debug().Msg("Ignoring empty request (likely browser auto-complete or pre-flight)")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(infoHTML("Waiting for Authentication", "Please complete the login in the Databricks window.")))
		return
	}

	// Send the response back to the CLI
	defer func() { tsp.authDoneCh <- resp }()

	// Do some checking of the response here to show more relevant content
	if resp.err != "" {
		log.Error().Msg(resp.err)
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(errorHTML("Identity Provider returned an error: " + resp.err)))
		if err != nil {
			log.Error().Err(err).Msg("unable to write error response")
		}
		return
	}
	if resp.state != tsp.state {
		msg := fmt.Sprintf("Authentication state mismatch: expected '%s', got '%s'. This may be from an old browser window.", tsp.state, resp.state)
		log.Warn().Msg(msg)
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(errorHTML("Authentication state mismatch. Please close this window and use the correct browser tab.")))
		if err != nil {
			log.Error().Err(err).Msg("unable to write error response")
		}
		return
	}

	_, err := w.Write([]byte(infoHTML("CLI Login Success", "You may close this window anytime now and go back to terminal")))
	if err != nil {
		log.Error().Err(err).Msg("unable to write success response")
	}
}

func GetTokenSourceProvider(ctx context.Context, config oauth2.Config, timeout time.Duration, tokenCache *tokenCache, hostname string) (*tokenSourceProvider, error) {
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, os.Interrupt)

	// receive auth callback response
	authDoneCh := make(chan authResponse)

	u, _ := url.Parse(config.RedirectURL)
	if u.Path == "" {
		u.Path = "/"
	}

	tsp := &tokenSourceProvider{
		timeout:     timeout,
		sigintCh:    sigintCh,
		authDoneCh:  authDoneCh,
		redirectURL: u,
		config:      config,
		tokenCache:  tokenCache,
		hostname:    hostname,
	}

	// Note: Handler registration happens in GetTokenSource() where
	// each server gets its own dedicated handler

	return tsp, nil
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
