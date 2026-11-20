package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const bodyMarker = "MODSECURITY-BENCH-MARKER"

var errUpstreamExited = errors.New("upstream exited before becoming ready")

type options struct {
	baseline       string
	candidate      string
	bodySizes      string
	bodyBufferSize int
	maxBodySize    int
	duration       time.Duration
	warmup         time.Duration
	requestTimeout time.Duration
	concurrency    int
	rounds         int
	serverCPU      string
	upstreamCPU    string
}

type metadata struct {
	Type           string            `json:"type"`
	GoVersion      string            `json:"go_version"`
	OS             string            `json:"os"`
	Arch           string            `json:"arch"`
	CPUs           int               `json:"cpus"`
	ClockTicks     int64             `json:"clock_ticks_per_second,omitempty"`
	ClockTickError string            `json:"clock_tick_error,omitempty"`
	Options        map[string]string `json:"options"`
	Binaries       []binaryInfo      `json:"binaries"`
}

type binaryInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"nginx_version"`
}

type sample struct {
	Type                 string  `json:"type"`
	Build                string  `json:"build"`
	Mode                 string  `json:"mode"`
	Round                int     `json:"round"`
	BodyBytes            int     `json:"body_bytes"`
	BodySHA256           string  `json:"body_sha256"`
	Concurrency          int     `json:"concurrency"`
	Requests             int64   `json:"requests"`
	ElapsedSeconds       float64 `json:"elapsed_seconds"`
	RequestsPerSecond    float64 `json:"requests_per_second"`
	BodyBytesPerSecond   float64 `json:"body_bytes_per_second"`
	P50LatencyMillis     float64 `json:"p50_latency_ms"`
	P95LatencyMillis     float64 `json:"p95_latency_ms"`
	P99LatencyMillis     float64 `json:"p99_latency_ms"`
	NginxCPUSeconds      float64 `json:"nginx_cpu_seconds,omitempty"`
	NginxCPUMicroseconds float64 `json:"nginx_cpu_microseconds_per_request,omitempty"`
}

type summary struct {
	Type                       string  `json:"type"`
	Build                      string  `json:"build"`
	Mode                       string  `json:"mode"`
	BodyBytes                  int     `json:"body_bytes"`
	Rounds                     int     `json:"rounds"`
	MedianRequestsSec          float64 `json:"median_requests_per_second"`
	MedianBodyBytesSec         float64 `json:"median_body_bytes_per_second"`
	MedianNginxCPUMicroseconds float64 `json:"median_nginx_cpu_microseconds_per_request,omitempty"`
	MedianP50Millis            float64 `json:"median_p50_latency_ms"`
	MedianP95Millis            float64 `json:"median_p95_latency_ms"`
	MedianP99Millis            float64 `json:"median_p99_latency_ms"`
}

type nginxServer struct {
	cmd     *exec.Cmd
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
	logFile *os.File
	port    int
	tempDir string
}

type cpuStat struct {
	ticks int64
}

type latencyValues struct {
	mu     sync.Mutex
	values []int64
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--upstream-helper" {
		if err := serveUpstream(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "benchmark upstream:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "request-body benchmark:", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseFlags()
	if err := validateOptions(opts); err != nil {
		return err
	}

	sizes, err := parseBodySizes(opts.bodySizes)
	if err != nil {
		return err
	}
	for _, size := range sizes {
		if size > opts.maxBodySize {
			return fmt.Errorf("body size %d exceeds --max-body-size %d", size, opts.maxBodySize)
		}
	}
	ticksPerSecond, tickErr := clockTicksPerSecond()

	binaries, err := collectBinaryInfo(opts.baseline, opts.candidate)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	meta := metadata{
		Type:           "metadata",
		GoVersion:      runtimeVersion,
		OS:             runtimeOS,
		Arch:           runtimeArch,
		CPUs:           runtimeCPUs,
		ClockTicks:     ticksPerSecond,
		Binaries:       binaries,
		ClockTickError: errorString(tickErr),
		Options: map[string]string{
			"body_sizes":              opts.bodySizes,
			"client_body_buffer_size": strconv.Itoa(opts.bodyBufferSize),
			"max_body_size":           strconv.Itoa(opts.maxBodySize),
			"duration":                opts.duration.String(),
			"warmup":                  opts.warmup.String(),
			"request_timeout":         opts.requestTimeout.String(),
			"concurrency":             strconv.Itoa(opts.concurrency),
			"rounds":                  strconv.Itoa(opts.rounds),
			"server_cpu":              opts.serverCPU,
			"upstream_cpu":            opts.upstreamCPU,
		},
	}
	if err := encoder.Encode(meta); err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "modsecurity-request-body-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	upstream, upstreamAddress, err := startUpstream(opts, tempDir)
	if err != nil {
		return err
	}
	defer upstream.stop()

	builds := []binaryInfo{binaries[0], binaries[1]}
	results := make(map[string][]sample)
	for round := 1; round <= opts.rounds; round++ {
		roundBuilds := builds
		if round%2 == 0 {
			roundBuilds = []binaryInfo{builds[1], builds[0]}
		}

		for _, binary := range roundBuilds {
			server, err := startNginx(binary.Path, upstreamAddress, opts, tempDir, round)
			if err != nil {
				return fmt.Errorf("start %s nginx: %w", binary.Name, err)
			}

			if err := verifyServer(server.port); err != nil {
				server.stop()
				return fmt.Errorf("verify %s nginx: %w", binary.Name, err)
			}

			modes := []string{"off", "inspect"}
			if round%2 == 0 {
				modes = []string{"inspect", "off"}
			}
			for _, bodySize := range sizes {
				body := makePayload(bodySize)
				if err := verifyBodyModes(server.port, body); err != nil {
					server.stop()
					return fmt.Errorf("verify %s body size %d: %w", binary.Name, bodySize, err)
				}

				for _, mode := range modes {
					path := "/" + mode
					metrics, before, after, err := runLoad(server.cmd.Process.Pid, server.port, path, body, opts)
					if err != nil {
						server.stop()
						return fmt.Errorf("run %s %s %d-byte case: %w", binary.Name, mode, bodySize, err)
					}

					result := makeSample(binary.Name, mode, round, body, opts.concurrency, metrics)
					if tickErr == nil && ticksPerSecond > 0 {
						result.NginxCPUSeconds = float64(after.ticks-before.ticks) / float64(ticksPerSecond)
						if result.Requests > 0 {
							result.NginxCPUMicroseconds = result.NginxCPUSeconds * 1e6 / float64(result.Requests)
						}
					}
					if err := encoder.Encode(result); err != nil {
						server.stop()
						return err
					}
					key := summaryKey(result.Build, result.Mode, result.BodyBytes)
					results[key] = append(results[key], result)
				}
			}

			if err := server.stop(); err != nil {
				return fmt.Errorf("stop %s nginx: %w", binary.Name, err)
			}
		}
	}

	for _, binary := range builds {
		for _, mode := range []string{"off", "inspect"} {
			for _, bodySize := range sizes {
				key := summaryKey(binary.Name, mode, bodySize)
				if err := encoder.Encode(makeSummary(results[key], opts.rounds)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Read benchmark host metadata from the standard library without adding
// external dependencies or a Go module to this repository.
var (
	runtimeVersion = runtime.Version()
	runtimeOS      = runtime.GOOS
	runtimeArch    = runtime.GOARCH
	runtimeCPUs    = runtime.NumCPU()
)

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.baseline, "baseline", "", "baseline nginx binary")
	flag.StringVar(&opts.candidate, "candidate", "", "candidate nginx binary")
	flag.StringVar(&opts.bodySizes, "body-sizes", "8192,65536,1048576", "comma-separated request body sizes in bytes")
	flag.IntVar(&opts.bodyBufferSize, "client-body-buffer-size", 16384, "nginx client_body_buffer_size in bytes")
	flag.IntVar(&opts.maxBodySize, "max-body-size", 8388608, "nginx and ModSecurity request body limit in bytes")
	flag.DurationVar(&opts.duration, "duration", 5*time.Second, "measurement duration per case")
	flag.DurationVar(&opts.warmup, "warmup", time.Second, "warmup duration per case")
	flag.DurationVar(&opts.requestTimeout, "request-timeout", 30*time.Second, "timeout for each HTTP request")
	flag.IntVar(&opts.concurrency, "concurrency", 4, "number of concurrent keep-alive clients")
	flag.IntVar(&opts.rounds, "rounds", 3, "number of alternating baseline/candidate rounds")
	flag.StringVar(&opts.serverCPU, "server-cpu", "", "optional CPU number for nginx (requires taskset)")
	flag.StringVar(&opts.upstreamCPU, "upstream-cpu", "", "optional CPU number for the local upstream (requires taskset)")
	flag.Parse()
	return opts
}

func validateOptions(opts options) error {
	if opts.baseline == "" || opts.candidate == "" {
		return errors.New("both --baseline and --candidate are required")
	}
	for _, binary := range []string{opts.baseline, opts.candidate} {
		info, err := os.Stat(binary)
		if err != nil {
			return fmt.Errorf("inspect nginx binary %q: %w", binary, err)
		}
		if info.IsDir() || info.Mode()&0111 == 0 {
			return fmt.Errorf("nginx binary %q is not an executable file", binary)
		}
	}
	if opts.bodyBufferSize <= 0 || opts.maxBodySize <= 0 {
		return errors.New("body buffer and maximum body size must be positive")
	}
	if opts.duration <= 0 || opts.warmup < 0 || opts.requestTimeout <= 0 {
		return errors.New("duration and request timeout must be positive; warmup cannot be negative")
	}
	if opts.concurrency <= 0 || opts.rounds <= 0 {
		return errors.New("concurrency and rounds must be positive")
	}
	for _, cpu := range []string{opts.serverCPU, opts.upstreamCPU} {
		if cpu == "" {
			continue
		}
		if _, err := exec.LookPath("taskset"); err != nil {
			return errors.New("CPU affinity options require taskset to be installed")
		}
		if _, err := strconv.Atoi(cpu); err != nil {
			return fmt.Errorf("invalid CPU number %q", cpu)
		}
	}
	return nil
}

func parseBodySizes(input string) ([]int, error) {
	var sizes []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		size, err := strconv.Atoi(part)
		if err != nil || size < len(bodyMarker) {
			return nil, fmt.Errorf("invalid body size %q: sizes must be integers at least %d bytes", part, len(bodyMarker))
		}
		if seen[size] {
			return nil, fmt.Errorf("duplicate body size %d", size)
		}
		seen[size] = true
		sizes = append(sizes, size)
	}
	if len(sizes) == 0 {
		return nil, errors.New("at least one body size is required")
	}
	return sizes, nil
}

func makePayload(size int) []byte {
	body := bytes.Repeat([]byte("x"), size)
	copy(body[len(body)-len(bodyMarker):], bodyMarker)
	return body
}

type upstreamServer struct {
	cmd  *exec.Cmd
	done chan error
}

func startUpstream(opts options, workDir string) (*upstreamServer, string, error) {
	address := filepath.Join(workDir, "upstream.sock")
	executable, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	command := executable
	args := []string{"--upstream-helper", address}
	if opts.upstreamCPU != "" {
		command = "taskset"
		args = []string{"-c", opts.upstreamCPU, executable, "--upstream-helper", address}
	}
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	server := &upstreamServer{cmd: cmd, done: make(chan error, 1)}
	go func() { server.done <- cmd.Wait() }()
	if err := waitForUpstream(address, server.done); err != nil {
		if !errors.Is(err, errUpstreamExited) {
			_ = server.stop()
		}
		return nil, "", err
	}
	return server, address, nil
}

func serveUpstream(address string) error {
	listener, err := net.Listen("unix", address)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.Serve(listener)
}

func waitForUpstream(address string, done <-chan error) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return fmt.Errorf("%w: %v", errUpstreamExited, err)
		default:
		}
		conn, err := net.DialTimeout("unix", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("timed out waiting for benchmark upstream")
}

func (server *upstreamServer) stop() error {
	if server == nil || server.cmd == nil || server.cmd.Process == nil {
		return nil
	}
	select {
	case err := <-server.done:
		return err
	default:
	}
	_ = server.cmd.Process.Kill()
	return <-server.done
}

func startNginx(binary, upstream string, opts options, workDir string, round int) (*nginxServer, error) {
	port, err := reservePort()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(workDir, "nginx-")
	if err != nil {
		return nil, err
	}
	bodyTemp := filepath.Join(dir, "client_body_temp")
	if err := os.Mkdir(bodyTemp, 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0700); err != nil {
		return nil, err
	}
	configPath := filepath.Join(dir, "nginx.conf")
	config := makeNginxConfig(port, upstream, bodyTemp, opts)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return nil, err
	}

	logFile, err := os.Create(filepath.Join(dir, "nginx.log"))
	if err != nil {
		return nil, err
	}
	args := []string{"-p", dir + string(os.PathSeparator), "-c", configPath}
	command := binary
	if opts.serverCPU != "" {
		command = "taskset"
		args = append([]string{"-c", opts.serverCPU, binary}, args...)
	}
	cmd := exec.Command(command, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	server := &nginxServer{
		cmd:     cmd,
		done:    make(chan struct{}),
		logFile: logFile,
		port:    port,
		tempDir: dir,
	}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	go func() {
		server.waitMu.Lock()
		server.waitErr = cmd.Wait()
		server.waitMu.Unlock()
		close(server.done)
	}()
	if err := waitForNginx(server); err != nil {
		logData, _ := os.ReadFile(filepath.Join(dir, "nginx.log"))
		server.stop()
		return nil, fmt.Errorf("round %d: %w; nginx log: %s", round, err, strings.TrimSpace(string(logData)))
	}
	return server, nil
}

func makeNginxConfig(port int, upstream, bodyTemp string, opts options) string {
	rules := fmt.Sprintf(`SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRule REQUEST_BODY "@contains %s" "id:100001,phase:request,pass,nolog"`, opts.maxBodySize, bodyMarker)
	denyRules := fmt.Sprintf(`SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRule REQUEST_BODY "@contains %s" "id:100002,phase:request,deny,log,status:403"`, opts.maxBodySize, bodyMarker)

	return fmt.Sprintf(`worker_processes 1;
daemon off;
master_process off;
pid %s;
error_log stderr crit;

events {
    worker_connections 4096;
}

http {
    access_log off;
    client_body_buffer_size %d;
    client_max_body_size %d;
    client_body_temp_path %s;
    keepalive_timeout 65;

    upstream benchmark_backend {
        server %s;
        keepalive 64;
    }

    server {
        listen 127.0.0.1:%d;
        modsecurity on;

        location = /off {
            modsecurity off;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://benchmark_backend;
        }

        location = /inspect {
            modsecurity_rules '%s';
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://benchmark_backend;
        }

        location = /deny {
            modsecurity_rules '%s';
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://benchmark_backend;
        }
    }
}
`, quoteNginx(filepath.Join(bodyTemp, "..", "nginx.pid")), opts.bodyBufferSize,
		opts.maxBodySize, quoteNginx(bodyTemp), quoteNginx("unix:"+upstream), port, rules, denyRules)
}

func quoteNginx(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func reservePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitForNginx(server *nginxServer) error {
	deadline := time.Now().Add(10 * time.Second)
	client := &http.Client{Timeout: 250 * time.Millisecond}
	defer client.CloseIdleConnections()
	for time.Now().Before(deadline) {
		select {
		case <-server.done:
			err := server.waitError()
			if err != nil {
				return fmt.Errorf("nginx exited before becoming ready: %w", err)
			}
			return errors.New("nginx exited before becoming ready")
		default:
		}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/off", server.port))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("timed out waiting for nginx")
}

func verifyServer(port int) error {
	return checkStatus(port, "/off", nil, http.StatusNoContent)
}

func verifyBodyModes(port int, body []byte) error {
	if err := checkStatus(port, "/off", body, http.StatusNoContent); err != nil {
		return fmt.Errorf("module-off control: %w", err)
	}
	if err := checkStatus(port, "/inspect", body, http.StatusNoContent); err != nil {
		return fmt.Errorf("inspection pass rule: %w", err)
	}
	if err := checkStatus(port, "/deny", body, http.StatusForbidden); err != nil {
		return fmt.Errorf("inspection blocking rule: %w", err)
	}
	return nil
}

func checkStatus(port int, path string, body []byte, expected int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != expected {
		return fmt.Errorf("got HTTP %d, want HTTP %d", resp.StatusCode, expected)
	}
	return nil
}

type loadMetrics struct {
	requests int64
	elapsed  time.Duration
	latency  []int64
}

func runLoad(pid, port int, path string, body []byte, opts options) (loadMetrics, cpuStat, cpuStat, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clients := make([]*http.Client, opts.concurrency)
	for i := range clients {
		clients[i] = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        1,
				MaxIdleConnsPerHost: 1,
				MaxConnsPerHost:     1,
				IdleConnTimeout:     90 * time.Second,
			},
			Timeout: opts.requestTimeout,
		}
	}
	defer func() {
		for _, client := range clients {
			client.CloseIdleConnections()
		}
	}()

	if opts.warmup > 0 {
		if _, err := loadPhase(ctx, clients, port, path, body, opts.warmup, false); err != nil {
			return loadMetrics{}, cpuStat{}, cpuStat{}, err
		}
	}
	before, beforeErr := readProcessCPU(pid)
	metrics, err := loadPhase(ctx, clients, port, path, body, opts.duration, true)
	after, afterErr := readProcessCPU(pid)
	if err != nil {
		return loadMetrics{}, cpuStat{}, cpuStat{}, err
	}
	if beforeErr != nil {
		return loadMetrics{}, cpuStat{}, cpuStat{}, fmt.Errorf("read nginx CPU counter before sample: %w", beforeErr)
	}
	if afterErr != nil {
		return loadMetrics{}, cpuStat{}, cpuStat{}, fmt.Errorf("read nginx CPU counter after sample: %w", afterErr)
	}
	return metrics, before, after, nil
}

func loadPhase(parent context.Context, clients []*http.Client, port int, path string, body []byte, duration time.Duration, collect bool) (loadMetrics, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	startGate := make(chan struct{})
	var wg sync.WaitGroup
	var completed int64
	var latencies latencyValues
	var firstErr error
	var errOnce sync.Once
	start := time.Now()
	deadline := start.Add(duration)

	for _, client := range clients {
		wg.Add(1)
		go func(client *http.Client) {
			defer wg.Done()
			<-startGate
			for time.Now().Before(deadline) {
				requestStart := time.Now()
				reqCtx, reqCancel := context.WithTimeout(ctx, client.Timeout)
				req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
					fmt.Sprintf("http://127.0.0.1:%d%s", port, path), bytes.NewReader(body))
				if err != nil {
					reqCancel()
					errOnce.Do(func() { firstErr = err; cancel() })
					return
				}
				req.Header.Set("Content-Type", "text/plain")
				req.ContentLength = int64(len(body))

				resp, err := client.Do(req)
				if err != nil {
					reqCancel()
					errOnce.Do(func() { firstErr = err; cancel() })
					return
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				closeErr := resp.Body.Close()
				reqCancel()
				if readErr != nil || closeErr != nil {
					errOnce.Do(func() {
						if readErr != nil {
							firstErr = readErr
						} else {
							firstErr = closeErr
						}
						cancel()
					})
					return
				}
				if resp.StatusCode != http.StatusNoContent {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("got HTTP %d from %s; want HTTP 204", resp.StatusCode, path)
						cancel()
					})
					return
				}
				atomic.AddInt64(&completed, 1)
				if collect {
					latencies.add(time.Since(requestStart).Nanoseconds())
				}
			}
		}(client)
	}

	start = time.Now()
	deadline = start.Add(duration)
	close(startGate)
	wg.Wait()
	elapsed := time.Since(start)
	if firstErr != nil {
		return loadMetrics{}, firstErr
	}
	values := latencies.sorted()
	return loadMetrics{requests: atomic.LoadInt64(&completed), elapsed: elapsed, latency: values}, nil
}

func (values *latencyValues) add(value int64) {
	values.mu.Lock()
	values.values = append(values.values, value)
	values.mu.Unlock()
}

func (values *latencyValues) sorted() []int64 {
	values.mu.Lock()
	defer values.mu.Unlock()
	sort.Slice(values.values, func(i, j int) bool { return values.values[i] < values.values[j] })
	return values.values
}

func makeSample(build, mode string, round int, body []byte, concurrency int, metrics loadMetrics) sample {
	rps := float64(metrics.requests) / metrics.elapsed.Seconds()
	hash := sha256.Sum256(body)
	result := sample{
		Type:               "sample",
		Build:              build,
		Mode:               mode,
		Round:              round,
		BodyBytes:          len(body),
		BodySHA256:         hex.EncodeToString(hash[:]),
		Concurrency:        concurrency,
		Requests:           metrics.requests,
		ElapsedSeconds:     metrics.elapsed.Seconds(),
		RequestsPerSecond:  rps,
		BodyBytesPerSecond: float64(metrics.requests*int64(len(body))) / metrics.elapsed.Seconds(),
		P50LatencyMillis:   percentileMillis(metrics.latency, 0.50),
		P95LatencyMillis:   percentileMillis(metrics.latency, 0.95),
		P99LatencyMillis:   percentileMillis(metrics.latency, 0.99),
	}
	return result
}

func percentileMillis(values []int64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values))*percentile+0.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return float64(values[index]) / float64(time.Millisecond)
}

func readProcessCPU(pid int) (cpuStat, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return cpuStat{}, err
	}
	closeParen := bytes.LastIndexByte(data, ')')
	if closeParen < 0 || closeParen+1 >= len(data) {
		return cpuStat{}, errors.New("malformed /proc process stat")
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	if len(fields) <= 12 {
		return cpuStat{}, errors.New("incomplete /proc process stat")
	}
	userTicks, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return cpuStat{}, err
	}
	systemTicks, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return cpuStat{}, err
	}
	return cpuStat{ticks: userTicks + systemTicks}, nil
}

func clockTicksPerSecond() (int64, error) {
	output, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("getconf returned an invalid CLK_TCK value")
	}
	return value, nil
}

func collectBinaryInfo(paths ...string) ([]binaryInfo, error) {
	names := []string{"baseline", "candidate"}
	result := make([]binaryInfo, 0, len(paths))
	for i, path := range paths {
		resolved, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		content, err := os.ReadFile(resolved)
		if err != nil {
			return nil, err
		}
		versionOutput, versionErr := exec.Command(resolved, "-V").CombinedOutput()
		if versionErr != nil {
			return nil, fmt.Errorf("%s nginx -V failed: %w: %s", names[i], versionErr, strings.TrimSpace(string(versionOutput)))
		}
		hash := sha256.Sum256(content)
		result = append(result, binaryInfo{
			Name:    names[i],
			Path:    resolved,
			SHA256:  hex.EncodeToString(hash[:]),
			Version: strings.TrimSpace(string(versionOutput)),
		})
	}
	return result, nil
}

func (server *nginxServer) stop() error {
	if server == nil || server.cmd == nil || server.cmd.Process == nil {
		return nil
	}
	select {
	case <-server.done:
		return server.cleanup(server.waitError())
	default:
	}
	_ = server.cmd.Process.Signal(os.Interrupt)
	select {
	case <-server.done:
		err := server.waitError()
		if err != nil {
			return server.cleanup(err)
		}
		return server.cleanup(nil)
	case <-time.After(5 * time.Second):
		_ = server.cmd.Process.Kill()
		<-server.done
		return server.cleanup(fmt.Errorf("nginx did not stop gracefully: %w", server.waitError()))
	}
}

func (server *nginxServer) waitError() error {
	server.waitMu.Lock()
	defer server.waitMu.Unlock()
	return server.waitErr
}

func (server *nginxServer) cleanup(err error) error {
	server.logFile.Close()
	os.RemoveAll(server.tempDir)
	return err
}

func summaryKey(build, mode string, bodyBytes int) string {
	return fmt.Sprintf("%s/%s/%d", build, mode, bodyBytes)
}

func makeSummary(samples []sample, rounds int) summary {
	result := summary{Type: "summary", Rounds: rounds}
	if len(samples) == 0 {
		return result
	}
	result.Build = samples[0].Build
	result.Mode = samples[0].Mode
	result.BodyBytes = samples[0].BodyBytes

	var rps, bytesSec, cpuUs, p50, p95, p99 []float64
	for _, current := range samples {
		rps = append(rps, current.RequestsPerSecond)
		bytesSec = append(bytesSec, current.BodyBytesPerSecond)
		if current.NginxCPUSeconds > 0 {
			cpuUs = append(cpuUs, current.NginxCPUMicroseconds)
		}
		p50 = append(p50, current.P50LatencyMillis)
		p95 = append(p95, current.P95LatencyMillis)
		p99 = append(p99, current.P99LatencyMillis)
	}
	result.MedianRequestsSec = median(rps)
	result.MedianBodyBytesSec = median(bytesSec)
	result.MedianNginxCPUMicroseconds = median(cpuUs)
	result.MedianP50Millis = median(p50)
	result.MedianP95Millis = median(p95)
	result.MedianP99Millis = median(p99)
	return result
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
