#!/usr/bin/perl

# Tests for the local address supplied to ModSecurity.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/)->plan(3);
my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        %%UNIX_LISTEN%%
        modsecurity on;
        modsecurity_rules 'SecRuleEngine On';
        location /ipv4 {
            modsecurity_rules '
                SecRule SERVER_ADDR "!@streq 127.0.0.1" "id:101,phase:1,deny,status:403"
            ';
        }
        location /unix {
            modsecurity_rules '
                SecRule SERVER_ADDR "!@streq unix:%%TESTDIR%%/server.sock" "id:102,phase:1,deny,status:403"
            ';
        }
    }
}
EOF
my $listen = $t->has_feature('unix')
    ? 'listen unix:%%TESTDIR%%/server.sock;' : '';
$conf =~ s/%%UNIX_LISTEN%%/$listen/;
$t->write_file_expand('nginx.conf', $conf);
$t->write_file('ipv4', 'OK');
$t->write_file('unix', 'OK');
$t->run();

like(http_get('/ipv4'), qr/^HTTP.*200/, 'IPv4 SERVER_ADDR is complete');
like(http_get('/unix'), qr/^HTTP.*403/, 'address rule rejects a different address');

SKIP: {
    skip 'no UNIX-domain sockets', 1 unless $t->has_feature('unix');
    require IO::Socket::UNIX;
    my $socket = IO::Socket::UNIX->new(
        Type => Socket::SOCK_STREAM(),
        Peer => $t->testdir() . '/server.sock'
    ) or die "Cannot connect to UNIX socket: $!";
    like(http("GET /unix HTTP/1.0\r\nHost: localhost\r\n\r\n",
        socket => $socket), qr/^HTTP.*200/,
        'UNIX SERVER_ADDR is complete and does not corrupt memory');
}