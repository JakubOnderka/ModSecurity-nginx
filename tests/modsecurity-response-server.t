#!/usr/bin/perl

# Tests for Date headers supplied to phase-three rules.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(4);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule &RESPONSE_HEADERS:Server "!@eq 1" "id:101,phase:3,deny,status:403"
        ';
        location /proxy {
            proxy_pass http://127.0.0.1:8081/;
            proxy_pass_header Server;
        }
    }
    server {
        listen 127.0.0.1:8081;
        return 200 "OK";
    }
}
EOF
$t->write_file('local', 'OK');
$t->run();

for my $path ('/local', '/proxy') {
    my $r = http_get($path);
    like($r, qr/^HTTP.*200/, "$path: phase three sees exactly one Server header");
    my @dates = $r =~ /^Server: ([^\r\n]+)/mg;
    is(scalar @dates, 1, "$path: client receives exactly one Server header");
}
