#!/usr/bin/perl

# Tests for Content-Length headers supplied to phase-three rules.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/)->plan(1);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        modsecurity on;
        modsecurity_rules 'SecRuleEngine On';

        location /empty {
            modsecurity_rules '
                SecRule RESPONSE_HEADERS:Content-Length "@streq 0" "id:101,phase:3,deny,status:403"
            ';
        }
}
EOF
$t->write_file('empty', '');
$t->run();

like(http_get('/empty'), qr/^HTTP.*403/, 'phase three sees Content-Length: 0');
