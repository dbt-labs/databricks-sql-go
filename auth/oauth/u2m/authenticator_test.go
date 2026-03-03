package u2m

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

type mockTokenSource struct {
	token *oauth2.Token
	err   error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.token, m.err
}

type mockTokenSourceProvider struct {
	sources []oauth2.TokenSource
	errs    []error
	calls   int
}

func (m *mockTokenSourceProvider) GetTokenSource() (oauth2.TokenSource, error) {
	if m.calls < len(m.errs) && m.errs[m.calls] != nil {
		err := m.errs[m.calls]
		m.calls++
		return nil, err
	}
	if m.calls >= len(m.sources) {
		m.calls++
		return nil, errors.New("unexpected GetTokenSource call")
	}
	src := m.sources[m.calls]
	m.calls++
	return src, nil
}

// first token source returns invalid_grant + nil token.
func TestAuthenticate_InvalidGrant_ReauthsWithoutPanic(t *testing.T) {
	first := &mockTokenSource{
		token: nil,
		err:   errors.New("oauth2: invalid_grant"),
	}
	secondToken := &oauth2.Token{
		AccessToken: "fresh-access-token",
		TokenType:   "Bearer",
	}
	second := &mockTokenSource{
		token: secondToken,
		err:   nil,
	}
	provider := &mockTokenSourceProvider{
		sources: []oauth2.TokenSource{first, second},
	}

	auth := &u2mAuthenticator{
		tsp: provider,
	}
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := auth.Authenticate(req); err != nil {
		t.Fatalf("authenticate should recover from invalid_grant: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer fresh-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if provider.calls != 2 {
		t.Fatalf("expected provider to be called twice, got %d", provider.calls)
	}
}

func TestAuthenticate_NonInvalidGrant_ReturnsError(t *testing.T) {
	src := &mockTokenSource{
		token: nil,
		err:   errors.New("network issue"),
	}
	provider := &mockTokenSourceProvider{
		sources: []oauth2.TokenSource{src},
	}

	auth := &u2mAuthenticator{
		tsp: provider,
	}
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := auth.Authenticate(req); err == nil {
		t.Fatal("expected non-invalid_grant error")
	}
	if provider.calls != 1 {
		t.Fatalf("expected provider to be called once, got %d", provider.calls)
	}
}

func TestAuthenticate_TokenTimeout_ReturnsError(t *testing.T) {
	src := &mockTokenSource{
		token: nil,
		err:   context.DeadlineExceeded,
	}
	provider := &mockTokenSourceProvider{
		sources: []oauth2.TokenSource{src},
	}

	auth := &u2mAuthenticator{
		tsp: provider,
	}
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	err = auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if provider.calls != 1 {
		t.Fatalf("expected provider to be called once, got %d", provider.calls)
	}
}

func TestAuthenticate_InvalidGrant_ReauthTimeout_ReturnsError(t *testing.T) {
	first := &mockTokenSource{
		token: nil,
		err:   errors.New("oauth2: invalid_grant"),
	}
	provider := &mockTokenSourceProvider{
		sources: []oauth2.TokenSource{first},
		errs:    []error{nil, context.DeadlineExceeded},
	}

	auth := &u2mAuthenticator{
		tsp: provider,
	}
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	err = auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected timeout error from re-auth")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if provider.calls != 2 {
		t.Fatalf("expected provider to be called twice, got %d", provider.calls)
	}
}
