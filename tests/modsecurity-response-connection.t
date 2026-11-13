#!/usr/bin/perl

# Tests for Keep-Alive headers supplied to phase-three rules.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/)->plan(4);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        keepalive_timeout 500ms 2147483647s;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule RESPONSE_HEADERS:Keep-Alive "!@streq timeout=2147483647" "id:101,phase:3,deny,status:403"
            SecRule REQUEST_HEADERS:Connection "@streq keep-alive" "id:102,phase:3,deny,status:403,chain"
                SecRule &RESPONSE_HEADERS:Keep-Alive "!@eq 1" "t:none"
            SecRule REQUEST_HEADERS:Connection "@streq close" "id:103,phase:3,deny,status:403,chain"
                SecRule &RESPONSE_HEADERS:Keep-Alive "!@eq 0" "t:none"
        ';
    }
}
EOF
$t->write_file('local', 'OK');
$t->run();

for my $connection ('keep-alive', 'close') {
    my $r = http(<<EOF);
GET /local HTTP/1.1
Host: localhost
Connection: $connection

EOF
    like($r, qr/^HTTP.*200/,
        "$connection: phase three sees the expected Keep-Alive header");
    if ($connection eq 'keep-alive') {
        like($r, qr/^Keep-Alive: timeout=2147483647\r?$/m,
            'client receives the complete timeout');
    } else {
        unlike($r, qr/^Keep-Alive:/m,
            'closed connection has no Keep-Alive header');
    }
}