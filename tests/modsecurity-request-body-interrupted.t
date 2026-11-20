#!/usr/bin/perl

# Tests for interrupted HTTP/1 request bodies.

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF SHUT_WR /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ http http_get http_start http_end /;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(35);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;

events {}

http {
    %%TEST_GLOBALS_HTTP%%
    log_format interrupted '$uri $status "$request_completion"';

    server {
        listen 127.0.0.1:8081;
        access_log %%TESTDIR%%/upstream.log interrupted;
        location / { return 200 "UPSTREAM"; }
    }

    server {
        listen 127.0.0.1:8080;
        client_body_temp_path %%TESTDIR%%/body;
        access_log %%TESTDIR%%/requests.log interrupted;
        client_body_buffer_size 128k;
        client_body_timeout 1s;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_BODY "@contains BAD BODY" "id:101,phase:2,deny,log,status:403"
        ';
        location / {
            proxy_pass http://127.0.0.1:8081;
        }
        location /file/ {
            client_body_buffer_size 128;
            client_body_in_file_only clean;
            proxy_pass http://127.0.0.1:8081;
        }
        location /storage-error {
            client_body_buffer_size 128;
            client_body_temp_path %%TESTDIR%%/unwritable;
            proxy_pass http://127.0.0.1:8081;
        }
        location /size-error {
            client_max_body_size 100;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF

$t->run();

foreach my $mode ('memory', 'file') {
    foreach my $kind ('length', 'chunked', 'timeout') {
        my $uri = "/$mode/$kind";
        my $headers = $kind eq 'chunked'
            ? 'Transfer-Encoding: chunked'
            : 'Content-Length: 65536';
        my $s = http_start("POST $uri HTTP/1.1" . CRLF
            . 'Host: localhost' . CRLF . $headers . CRLF
            . 'Connection: close' . CRLF . CRLF);
        my $body = 'BAD BODY' . 'x' x 16376;

        # Send only part of the promised body (or of a single HTTP chunk).
        $s->print(($kind eq 'chunked' ? '10000' . CRLF : '') . $body)
            or die "Can't send partial body: $!";
        if ($mode eq 'file') {
            ok(wait_for(sub { scalar body_files() }),
                "$kind: body spills to disk before interruption");
        }

        shutdown($s, SHUT_WR) or die "Can't shut down upload: $!"
            unless $kind eq 'timeout';
        is(http_end($s), '',
            "$mode $kind: incomplete upload connection closed");
        my $code = $kind eq 'timeout' ? 408 : 400;
        ok(wait_for(sub {
            $t->read_file('requests.log') =~ /^\Q$uri\E $code ""$/m
        }), "$mode $kind: interrupted request finalized");
        ok(wait_for(sub { !scalar body_files() }),
            "$mode $kind: temporary body files released");
        like(http_get("/$mode/recovered-$kind"), qr/UPSTREAM/,
            "$mode $kind: worker still accepts requests");
    }
}

like(http('POST /blocked HTTP/1.1' . CRLF
    . 'Host: localhost' . CRLF . 'Connection: close' . CRLF
    . 'Content-Length: 8' . CRLF . CRLF . 'BAD BODY'),
    qr/^HTTP.*403/, 'complete malicious body is still inspected');

my $path = $t->testdir() . '/unwritable';
rmdir $path or die "Can't remove body temp directory: $!";
open my $blocker, '>', $path or die "Can't block body temp path: $!";
close $blocker;
my $s = http_start('POST /storage-error HTTP/1.1' . CRLF
    . 'Host: localhost' . CRLF . 'Content-Length: 65536' . CRLF
    . 'Connection: close' . CRLF . CRLF);
select undef, undef, undef, 0.1;
$s->print('x' x 1024) or die "Can't send partial body: $!";
shutdown($s, SHUT_WR);
like(http_end($s), qr/^HTTP.*500/, 'asynchronous body file failure returns 500');
ok(wait_for(sub { $t->read_file('requests.log') =~ m{^/storage-error 500 }m }),
    'body file failure finalizes the request');
like(http_get('/recovered-storage'), qr/UPSTREAM/,
    'worker accepts requests after body file failure');

$s = http_start('POST /size-error HTTP/1.1' . CRLF
    . 'Host: localhost' . CRLF . 'Transfer-Encoding: chunked' . CRLF
    . 'Connection: close' . CRLF . CRLF);
select undef, undef, undef, 0.1;
$s->print('65' . CRLF . ('x' x 101) . CRLF . '0' . CRLF . CRLF)
    or die "Can't send chunked body: $!";
shutdown($s, SHUT_WR);
like(http_end($s), qr/^HTTP.*413/, 'asynchronous chunked body limit returns 413');
ok(wait_for(sub { $t->read_file('requests.log') =~ m{^/size-error 413 }m }),
    'chunked body limit finalizes the request');
like(http_get('/recovered-size'), qr/UPSTREAM/,
    'worker accepts requests after chunked body limit');

$t->stop();
unlike($t->read_file('upstream.log'), qr{/(memory|file)/(length|chunked|timeout)\s},
    'no interrupted body was forwarded upstream');
undef $t;

sub body_files {
    my @files = glob($t->testdir() . '/body/*');
    return @files;
}

sub wait_for {
    my ($check) = @_;
    for (1 .. 50) {
        return 1 if $check->();
        select undef, undef, undef, 0.1;
    }
    return 0;
}
