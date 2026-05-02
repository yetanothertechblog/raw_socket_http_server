package http

import "testing"

// helper: register a handler that just records the pattern it was called for
// and writes that pattern as the response body, so tests can verify routing.
func recordingHandler(label string) HandlerFunc {
	return func(req *Request, w *ResponseWriter) {
		w.Write([]byte(label))
	}
}

// dispatch a path through mux and return the handler's body, or "" for 404.
func dispatch(mux *ServeMux, path string) string {
	resp := mux.Handle(&Request{Method: "GET", Path: path})
	if resp.StatusCode == 404 {
		return ""
	}
	return string(resp.Body)
}

func TestServeMux_ExactMatch(t *testing.T) {
	mux := NewServeMux()
	mux.RegisterHandler("/healthz", recordingHandler("healthz"))

	if got := dispatch(mux, "/healthz"); got != "healthz" {
		t.Errorf("/healthz routed to %q, want healthz", got)
	}
	if got := dispatch(mux, "/healthz/extra"); got != "" {
		t.Errorf("/healthz/extra should not match exact /healthz, got %q", got)
	}
}

func TestServeMux_PrefixMatch(t *testing.T) {
	mux := NewServeMux()
	mux.RegisterHandler("/static/", recordingHandler("static"))

	if got := dispatch(mux, "/static/foo.css"); got != "static" {
		t.Errorf("/static/foo.css routed to %q, want static", got)
	}
	if got := dispatch(mux, "/static/"); got != "static" {
		t.Errorf("/static/ should match its own prefix, got %q", got)
	}
	if got := dispatch(mux, "/static"); got != "" {
		t.Errorf("/static (no trailing slash) should not match prefix /static/, got %q", got)
	}
}

func TestServeMux_LongestPrefixWins(t *testing.T) {
	mux := NewServeMux()
	mux.RegisterHandler("/api/", recordingHandler("api"))
	mux.RegisterHandler("/api/v2/", recordingHandler("api-v2"))

	if got := dispatch(mux, "/api/v2/users"); got != "api-v2" {
		t.Errorf("/api/v2/users should pick longer /api/v2/, got %q", got)
	}
	if got := dispatch(mux, "/api/v1/users"); got != "api" {
		t.Errorf("/api/v1/users should fall back to /api/, got %q", got)
	}
}

func TestServeMux_ExactBeatsPrefix(t *testing.T) {
	mux := NewServeMux()
	mux.RegisterHandler("/api/", recordingHandler("api-prefix"))
	mux.RegisterHandler("/api/health", recordingHandler("api-health-exact"))

	if got := dispatch(mux, "/api/health"); got != "api-health-exact" {
		t.Errorf("exact /api/health should beat prefix /api/, got %q", got)
	}
	if got := dispatch(mux, "/api/health/details"); got != "api-prefix" {
		t.Errorf("/api/health/details has no exact match, should fall to prefix, got %q", got)
	}
}

func TestServeMux_RootIsCatchAll(t *testing.T) {
	// "/" ends in "/", so it's a prefix pattern matching every path.
	// This is the documented stdlib-style behavior.
	mux := NewServeMux()
	mux.RegisterHandler("/", recordingHandler("root"))
	mux.RegisterHandler("/healthz", recordingHandler("healthz"))

	if got := dispatch(mux, "/"); got != "root" {
		t.Errorf("/ should hit root handler, got %q", got)
	}
	if got := dispatch(mux, "/anything"); got != "root" {
		t.Errorf("/anything should hit root catch-all, got %q", got)
	}
	// Exact still beats catch-all.
	if got := dispatch(mux, "/healthz"); got != "healthz" {
		t.Errorf("/healthz should beat root catch-all, got %q", got)
	}
}

func TestServeMux_NoMatchIs404(t *testing.T) {
	mux := NewServeMux()
	mux.RegisterHandler("/foo", recordingHandler("foo"))

	resp := mux.Handle(&Request{Method: "GET", Path: "/bar"})
	if resp.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", resp.StatusCode)
	}
	if string(resp.Body) != "404 Not Found\n" {
		t.Errorf("Body = %q", resp.Body)
	}
}

func TestServeMux_TrailingSlashDistinguishes(t *testing.T) {
	// /foo and /foo/ are different patterns: the first is exact, the second
	// is a prefix. /foo only matches /foo; /foo/ matches /foo/anything.
	mux := NewServeMux()
	mux.RegisterHandler("/foo", recordingHandler("foo-exact"))
	mux.RegisterHandler("/foo/", recordingHandler("foo-prefix"))

	if got := dispatch(mux, "/foo"); got != "foo-exact" {
		t.Errorf("/foo should hit exact, got %q", got)
	}
	if got := dispatch(mux, "/foo/"); got != "foo-prefix" {
		t.Errorf("/foo/ should hit prefix, got %q", got)
	}
	if got := dispatch(mux, "/foo/bar"); got != "foo-prefix" {
		t.Errorf("/foo/bar should hit prefix, got %q", got)
	}
}
