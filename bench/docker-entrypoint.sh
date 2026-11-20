#!/bin/sh
set -eu
cat /opt/benchmark/revisions.txt >&2
exec taskset -c 1 /opt/benchmark/request-body-bench \
    --baseline /opt/benchmark/nginx-baseline \
    --candidate /opt/benchmark/nginx-candidate \
    --server-cpu 0 --upstream-cpu 2 "$@"