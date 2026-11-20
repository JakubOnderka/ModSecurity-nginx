#!/usr/bin/perl

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF SHUT_WR /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ http_get http_start http_end /;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(6);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8081;
        location / { return 200 "UPSTREAM"; }
    }
    server {
        listen 127.0.0.1:8080;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_BODY "@contains BAD BODY" "id:101,phase:2,deny,status:403"
        ';
        location / { proxy_pass http://127.0.0.1:8081; }
    }
}
EOF

$t->run();

my $s = http_start('POST /unbuffered-test HTTP/1.1' . CRLF
    . 'Host: localhost' . CRLF . 'Content-Length: 8' . CRLF
    . 'Connection: close' . CRLF . CRLF);
select undef, undef, undef, 0.1;
shutdown($s, SHUT_WR);
like(http_end($s), qr/^HTTP.*500/,
    'partially read unbuffered body is rejected before phase 2');
like(http_get('/unbuffered-flag'), qr/^HTTP.*500/,
    'unbuffered mode is rejected before starting a body read');

$s = http_start('POST /discarded-test HTTP/1.1' . CRLF
    . 'Host: localhost' . CRLF . 'Content-Length: 8' . CRLF
    . 'Connection: close' . CRLF . CRLF);
select undef, undef, undef, 0.1;
shutdown($s, SHUT_WR);
like(http_end($s), qr/^HTTP.*500/,
    'discarded body without request-body storage fails explicitly');

like(http_get('/healthy'), qr/UPSTREAM/, 'worker remains healthy');
$t->stop();
like($t->read_file('error.log'),
    qr/modsecurity: cannot inspect a request body already being read without buffering/,
    'unbuffered body rejection explains the error');
like($t->read_file('error.log'),
    qr/modsecurity: missing request body after body read/,
    'missing request body rejection explains the error');