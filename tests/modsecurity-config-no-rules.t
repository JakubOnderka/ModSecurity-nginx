#!/usr/bin/perl

# Test ModSecurity enabled with no rules configured anywhere.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity on;

    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;

        location / {
            try_files /response.txt =404;
        }
    }
}
EOF

$t->write_file('response.txt', 'TEST-OK-IF-YOU-SEE-THIS');
$t->run();

$t->plan(1);

like(http_get('/'), qr/^HTTP\/1\.[01] 200\b.*TEST-OK-IF-YOU-SEE-THIS/s,
    'ModSecurity enabled with no rules permits the request');