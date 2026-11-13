#!/usr/bin/perl

# Tests empty parent rulesets when rules are declared only in a child block.

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

        location /rules {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq local" "id:1,phase:1,deny,status:403"
            ';
            root %%TESTDIR%%;
            try_files /response.txt =404;
        }

        location /sibling {
            root %%TESTDIR%%;
            try_files /response.txt =404;
        }
    }

    server {
        listen 127.0.0.1:%%PORT_8081%%;
        server_name localhost;

        location / {
            root %%TESTDIR%%;
            try_files /response.txt =404;
        }
    }
}
EOF

$t->write_file('response.txt', 'TEST-OK-IF-YOU-SEE-THIS');
$t->run();

$t->plan(3);

like(http_get('/rules?a=local'), qr/403/, 'child rules work with empty http parent ruleset');
like(http_get('/sibling?a=local'), qr/TEST-OK-IF-YOU-SEE-THIS/,
    'child rules do not leak into sibling with empty parent ruleset');
like(http_request('GET', '/', port(8081)), qr/TEST-OK-IF-YOU-SEE-THIS/,
    'server with no local rules uses empty parent ruleset');

sub http_request {
    my ($method, $uri, $port) = @_;
    return http("$method $uri HTTP/1.0\r\nHost: localhost\r\n\r\n",
        PeerAddr => '127.0.0.1:' . $port);
}
