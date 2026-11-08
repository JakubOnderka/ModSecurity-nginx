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
