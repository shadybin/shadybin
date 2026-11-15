package review

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain has every test retry without waiting: tests that expect a fetch to fail would
// otherwise each wait out the pauses.
func TestMain(m *testing.M) {
	retryWaits = []time.Duration{0, 0}
	os.Exit(m.Run())
}

func TestRetry(t *testing.T) {
	ctx := context.Background()
	tries := 0
	if err := retry(ctx, io.Discard, "x", func() error {
		if tries++; tries < 3 {
			return errors.New("connection reset")
		}
		return nil
	}); err != nil || tries != 3 {
		t.Fatalf("a download that works on its third try: %v after %d tries", err, tries)
	}

	tries = 0
	if err := retry(ctx, io.Discard, "x", func() error { tries++; return errors.New("down") }); err == nil || tries != 3 {
		t.Fatalf("a download that never works: %v after %d tries", err, tries)
	}

	tries = 0
	err := retry(ctx, io.Discard, "x", func() error { tries++; return final(errors.New("wrong hash")) })
	if err == nil || err.Error() != "wrong hash" || tries != 1 {
		t.Fatalf("a final failure: %v after %d tries", err, tries)
	}
}

func TestDownload(t *testing.T) {
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		switch {
		case r.URL.Path == "/flaky" && hits["/flaky"] < 3:
			w.WriteHeader(http.StatusBadGateway)
		case r.URL.Path == "/flaky", r.URL.Path == "/big":
			w.Write([]byte(strings.Repeat("x", 10)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	if data, err := download(ctx, io.Discard, srv.URL+"/flaky", 100); err != nil || string(data) != strings.Repeat("x", 10) {
		t.Fatalf("a server that fails twice, then answers: %q, %v", data, err)
	}
	if _, err := download(ctx, io.Discard, srv.URL+"/missing", 100); err == nil || hits["/missing"] != 1 {
		t.Fatalf("a 404 is final: %v after %d tries", err, hits["/missing"])
	}
	if data, err := download(ctx, io.Discard, srv.URL+"/big", 4); err != nil || len(data) != 5 {
		t.Fatalf("a body over the limit comes back one byte over: %d bytes, %v", len(data), err)
	}
}
