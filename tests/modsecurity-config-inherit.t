#!/usr/bin/perl

# Tests for ruleset inheritance across configuration blocks.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity on;
    modsecurity_rules '
        SecRuleEngine On
        SecRule ARGS "@streq global" "id:100,phase:1,deny,status:403"
    ';

    server {
        listen 127.0.0.1:%%PORT_8080%%;
        server_name localhost;

        location /rules {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq local" "id:1,phase:1,deny,status:403"
            ';

            location /rules/nested {
                try_files /response.txt =404;
            }
            try_files /response.txt =404;
        }

        location /limited {
            limit_except GET {
                allow all;
            }
            try_files /response.txt =404;
        }

        location /file {
            modsecurity_rules_file %%TESTDIR%%/rules.conf;

            location /file/nested {
                try_files /response.txt =404;
            }
            try_files /response.txt =404;
        }

        location /conditional {
            modsecurity_rules '
                SecRule ARGS "@streq conditional" "id:3,phase:1,deny,status:403"
            ';

            if ($arg_x) {
                set $test_if 1;
            }
            try_files /response.txt =404;
        }

        location /sibling {
            try_files /response.txt =404;
        }
    }

    server {
        listen 127.0.0.1:%%PORT_8081%%;
        server_name localhost;

        location / {
            try_files /response.txt =404;
        }
    }
}
EOF

$t->write_file('rules.conf',
    'SecRule ARGS "@streq file" "id:4,phase:1,deny,status:403"');
$t->write_file('response.txt', 'TEST-OK-IF-YOU-SEE-THIS');

$t->run();

$t->plan(12);

like(http_get('/rules?a=local'), qr/403/, 'location rules apply');
like(http_get('/rules?a=global'), qr/403/, 'location rules retain inherited http rules');
like(http_get('/rules/nested?a=local'), qr/403/, 'location rules inherited by nested location');
like(http_get('/sibling?a=local'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'rules do not leak to sibling');
like(http_get('/sibling?a=global'), qr/403/, 'http rules inherited by sibling location');
like(http_get('/file?a=file'), qr/403/, 'rules file applies');
like(http_get('/file/nested?a=file'), qr/403/, 'rules file inherited by nested location');
like(http_get('/sibling?a=file'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'rules file does not leak to sibling');
like(http_get('/conditional?x=1&a=conditional'), qr/403/, 'if block inherits location rules');
like(http_request('GET', '/limited?a=clean', port(8080)),
    qr/TEST-OK-IF-YOU-SEE-THIS/, 'limit_except location accepts clean GET');
like(http_request('POST', '/limited?a=global', port(8080)),
    qr/403/, 'limit_except block inherits http rules');
like(http_request('GET', '/?a=local', port(8081)),
    qr/TEST-OK-IF-YOU-SEE-THIS/, 'rules do not leak to another server');

sub http_request {
    my ($method, $uri, $port) = @_;
    return http("$method $uri HTTP/1.0\r\nHost: localhost\r\n\r\n",
        PeerAddr => '127.0.0.1:' . $port);
}
