FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates curl git golang-go \
        libcurl4-gnutls-dev libmaxminddb-dev libpcre2-dev libssl-dev \
        libtool libxml2-dev libyajl-dev pkg-config util-linux \
    && rm -rf /var/lib/apt/lists/*

ARG MODSECURITY_VERSION=3.0.17
ARG NGINX_VERSION=1.31.8
ARG BUILD_JOBS=2

WORKDIR /build

RUN set -eu; \
    curl -fsSL "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${MODSECURITY_VERSION}/modsecurity-v${MODSECURITY_VERSION}.tar.gz" -o modsecurity.tar.gz; \
    curl -fsSL "https://github.com/nginx/nginx/releases/download/release-${NGINX_VERSION}/nginx-${NGINX_VERSION}.tar.gz" -o nginx.tar.gz; \
    mkdir modsecurity nginx-baseline nginx-candidate; \
    tar -xzf modsecurity.tar.gz -C modsecurity --strip-components=1; \
    tar -xzf nginx.tar.gz -C nginx-baseline --strip-components=1; \
    tar -xzf nginx.tar.gz -C nginx-candidate --strip-components=1; \
    cd modsecurity; \
    ./build.sh; \
    ./configure --without-lmdb --prefix=/opt/modsecurity; \
    make -j"$BUILD_JOBS"; \
    make install

ARG BASELINE_CONNECTOR_URL=https://github.com/JakubOnderka/ModSecurity-nginx.git
ARG BASELINE_CONNECTOR_REF=master
ARG CANDIDATE_CONNECTOR_URL=https://github.com/JakubOnderka/ModSecurity-nginx.git
ARG CANDIDATE_CONNECTOR_REF=request-body-processing2
RUN set -eu; \
    git init connector-baseline; \
    git -C connector-baseline remote add origin "$BASELINE_CONNECTOR_URL"; \
    git -C connector-baseline fetch --depth 1 origin "$BASELINE_CONNECTOR_REF"; \
    git -C connector-baseline checkout --detach FETCH_HEAD; \
    git init connector-candidate; \
    git -C connector-candidate remote add origin "$CANDIDATE_CONNECTOR_URL"; \
    git -C connector-candidate fetch --depth 1 origin "$CANDIDATE_CONNECTOR_REF"; \
    git -C connector-candidate checkout --detach FETCH_HEAD; \
    mkdir -p /opt/benchmark; \
    printf 'baseline %s %s %s\ncandidate %s %s %s\n' \
        "$BASELINE_CONNECTOR_URL" "$BASELINE_CONNECTOR_REF" "$(git -C connector-baseline rev-parse HEAD)" \
        "$CANDIDATE_CONNECTOR_URL" "$CANDIDATE_CONNECTOR_REF" "$(git -C connector-candidate rev-parse HEAD)" \
        > /opt/benchmark/revisions.txt; \
    for build in baseline candidate; do \
        cd "/build/nginx-$build"; \
        MODSECURITY_INC=/opt/modsecurity/include MODSECURITY_LIB=/opt/modsecurity/lib \
            ./configure --with-http_v2_module --with-http_v3_module \
                --with-http_ssl_module --with-http_auth_request_module \
                --without-http_gzip_module --add-module="/build/connector-$build"; \
        make -j"$BUILD_JOBS"; \
        cp objs/nginx "/opt/benchmark/nginx-$build"; \
    done; \
    ldd /opt/benchmark/nginx-baseline; \
    ldd /opt/benchmark/nginx-candidate

COPY request_body_bench.go /build/request_body_bench.go
RUN CGO_ENABLED=0 go build -o /opt/benchmark/request-body-bench /build/request_body_bench.go

RUN mkdir -p /usr/local/nginx/proxy_temp && \
    mkdir -p /usr/local/nginx/fastcgi_temp && \
    mkdir -p /usr/local/nginx/uwsgi_temp && \
    mkdir -p /usr/local/nginx/scgi_temp

COPY docker-entrypoint.sh /opt/benchmark/entrypoint.sh
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/bin/sh", "/opt/benchmark/entrypoint.sh"]