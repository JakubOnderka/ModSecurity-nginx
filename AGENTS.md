# Building and testing

- Build libModSecurity from source for this repository. Do not use a
  distribution-provided ModSecurity library or development package.
- Keep build dependencies and artifacts outside the connector checkout. Use a
  private install prefix rather than installing libModSecurity system-wide.
- Match the ModSecurity and Nginx versions in `.github/workflows/test.yml` when
  possible. The workflow is the reference for required build features and test
  dependencies; do not silently skip tests for missing dependencies.
- On Debian/Ubuntu, the source build needs a C/C++ toolchain, make, autoconf,
  automake, libtool, pkg-config, PCRE2, YAJL, libxml2, and OpenSSL development
  headers. The test harness also needs Perl, `prove`, OpenSSL, and CryptX for
  HTTP/3 tests. Install missing prerequisites only when needed.
- If Nginx, libModSecurity, or the Nginx test harness is not already available,
  follow the source-build example below in a separate writable build directory.
  Do not treat missing preinstalled tools as a reason to skip the relevant tests.
  If setup is blocked, report the specific blocker and which checks could not run.

The following Linux example uses the versions in the workflow at the time these
instructions were written. Run it from the connector checkout, replacing
`WORK` with an absolute path to a separate writable build directory:

```sh
CONNECTOR="$(pwd)"
WORK=/path/to/separate/build-directory
mkdir -p "$WORK"
cd "$WORK"

curl -fL -o modsecurity.tar.gz \
  https://github.com/owasp-modsecurity/ModSecurity/releases/download/v3.0.17/modsecurity-v3.0.17.tar.gz
curl -fL -o nginx.tar.gz \
  https://github.com/nginx/nginx/releases/download/release-1.31.8/nginx-1.31.8.tar.gz
git clone https://github.com/nginx/nginx-tests.git nginx-tests
mkdir modsecurity-src nginx
tar -xzf modsecurity.tar.gz -C modsecurity-src --strip-components=1
tar -xzf nginx.tar.gz -C nginx --strip-components=1

cd "$WORK/modsecurity-src"
./build.sh
./configure --without-lmdb --prefix="$WORK/modsecurity-install"
make -j 4
make install

cd "$WORK/nginx"
MODSECURITY_INC="$WORK/modsecurity-install/include" \
MODSECURITY_LIB="$WORK/modsecurity-install/lib" \
  ./configure --with-http_v2_module --with-http_v3_module \
  --with-http_ssl_module --with-http_auth_request_module \
  --add-module="$CONNECTOR"
make -j 4
```

Check `ldd "$WORK/nginx/objs/nginx"` on Linux to verify that libModSecurity
resolves to the private source-built prefix. Run the smallest relevant test set
from the connector's test directory, using the Nginx test harness:

```sh
cd "$CONNECTOR/tests"
TEST_NGINX_BINARY="$WORK/nginx/objs/nginx" \
PERL5LIB="$WORK/nginx-tests/lib" \
  prove modsecurity-request-body.t
```

Select other `modsecurity-*.t` files as appropriate; use `prove modsecurity*.t`
for the full suite. If running tests as root in an isolated test environment,
`TEST_NGINX_GLOBALS='user root;'` avoids permission failures when the test
directory is inaccessible to Nginx's default unprivileged worker. Never use
that setting for a production server.

## Benchmarking request-body inspection

The Go benchmark has no third-party dependencies. It requires Linux, Go,
`getconf`, `taskset`, and two executable Nginx binaries built with this
connector and libModSecurity. Build baseline and candidate in separate clean
directories, using the same Nginx and libModSecurity versions, compiler, flags,
and configuration; vary only the connector revision. Use release builds
without `--with-debug` and verify both binaries with `nginx -V` and `ldd`.

From the connector checkout, run:

 ```sh
 taskset -pc $$
 GO111MODULE=off taskset -c 1 go run bench/request_body_bench.go \
   --baseline "$WORK/nginx-baseline/objs/nginx" \
   --candidate "$WORK/nginx-candidate/objs/nginx" \
   --server-cpu 0 --upstream-cpu 2 \
   --duration 10s --warmup 1s --rounds 5 --concurrency 4 \
   | tee "$WORK/request-body-benchmark.jsonl"
 ```

Choose three distinct CPUs allowed by the current affinity mask: the command
pins the Go load generator to CPU 1, Nginx to CPU 0, and the local body-draining
upstream to CPU 2. Change these values if those CPUs are unavailable. The
benchmark alternates baseline/candidate order by round and switches the order
of the module-off and inspection cases. Each measured case is warmed up first.

By default, the runner sends deterministic 8 KiB, 64 KiB, and 1 MiB POST bodies
with a matching marker at the end. With the default 16 KiB
`client_body_buffer_size`, the smallest body exercises in-memory inspection
and the larger bodies exercise the client-body temp-file path. It checks that
the module-off control and the passing inspection rule return HTTP 204, and
that a separate blocking rule returns HTTP 403, before measuring. The upstream
drains each body and returns HTTP 204. Access logging is disabled and upstream
keep-alive is enabled in the generated Nginx configuration.

The JSONL output includes binary versions and hashes, fixture hashes,
per-round requests/sec, body throughput, p50/p95/p99 latency, and Nginx CPU
time per request, followed by median summaries. Keep the raw output; report
body sizes, buffer size, concurrency, CPU affinity, versions, and host
contention with any comparison. The benchmark removes its temporary Nginx
configurations and stops its processes on exit. Run its unit tests with
`GO111MODULE=off go test ./bench`.