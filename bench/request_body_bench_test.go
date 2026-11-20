package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseBodySizes(t *testing.T) {
	sizes, err := parseBodySizes("8192, 65536,1048576")
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 3 || sizes[0] != 8192 || sizes[2] != 1048576 {
		t.Fatalf("unexpected sizes: %v", sizes)
	}

	for _, input := range []string{"", "0", "abc", "24,24"} {
		if _, err := parseBodySizes(input); err == nil {
			t.Errorf("parseBodySizes(%q) unexpectedly succeeded", input)
		}
	}
}

func TestMakePayload(t *testing.T) {
	body := makePayload(128)
	if len(body) != 128 {
		t.Fatalf("payload size = %d, want 128", len(body))
	}
	if !bytes.HasSuffix(body, []byte(bodyMarker)) {
		t.Fatalf("payload does not end with marker")
	}
	if !bytes.Equal(body[:len(body)-len(bodyMarker)], bytes.Repeat([]byte("x"), 128-len(bodyMarker))) {
		t.Fatalf("payload prefix is not deterministic")
	}
}

func TestPercentileMillis(t *testing.T) {
	values := []int64{1_000_000, 2_000_000, 3_000_000, 4_000_000}
	if got := percentileMillis(values, 0.50); got != 2 {
		t.Errorf("p50 = %v, want 2", got)
	}
	if got := percentileMillis(values, 0.99); got != 4 {
		t.Errorf("p99 = %v, want 4", got)
	}
}

func TestMakeNginxConfigHasMemoryAndSpillWorkloadSettings(t *testing.T) {
	config := makeNginxConfig(18080, "127.0.0.1:18081", "/tmp/body-temp", options{
		bodyBufferSize: 16384,
		maxBodySize:    8388608,
	})
	for _, expected := range []string{
		"client_body_buffer_size 16384;",
		"client_body_temp_path",
		"location = /off",
		"location = /inspect",
		"location = /deny",
		"keepalive 64;",
		"proxy_pass http://benchmark_backend;",
		"SecRequestBodyAccess On",
		`@contains ` + bodyMarker,
	} {
		if !strings.Contains(config, expected) {
			t.Errorf("generated config missing %q", expected)
		}
	}
}

func TestLoadPhase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	clients := []*http.Client{{Timeout: time.Second}}
	metrics, err := loadPhase(context.Background(), clients, port, "/inspect",
		makePayload(128), 50*time.Millisecond, true)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.requests == 0 || len(metrics.latency) != int(metrics.requests) {
		t.Fatalf("unexpected measurement: %d requests, %d latencies", metrics.requests, len(metrics.latency))
	}
	if metrics.elapsed < 50*time.Millisecond {
		t.Fatalf("elapsed %v is shorter than requested measurement window", metrics.elapsed)
	}
}
