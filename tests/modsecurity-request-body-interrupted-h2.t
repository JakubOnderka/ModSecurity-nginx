#!/usr/bin/perl

# Tests for interrupted HTTP/2 request bodies.

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(21);

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
        http2 on;
        client_body_temp_path %%TESTDIR%%/body;
        access_log %%TESTDIR%%/requests.log interrupted;
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
    }
}
EOF

$t->run();

foreach my $mode ('memory', 'file') {
    my $s = Test::Nginx::HTTP2->new();
    my $sid = $s->new_stream({
        method => 'POST', path => "/$mode/reset", body_more => 1
    });
    $s->h2_body('BAD BODY' . 'x' x 1016, { body_more => 1 });
    if ($mode eq 'file') {
        ok(wait_for(sub { scalar body_files() }),
            'body spills to disk before RST_STREAM');
    }

    my $other = $s->new_stream({ path => '/parallel', body => 'GOOD' });
    is(status($s, $other), 200, "$mode: parallel stream completes");
    $s->h2_rst($sid, 8);
    ok(wait_for(sub {
        $t->read_file('requests.log') =~ m{^/$mode/reset 499 ""$}m
    }), "$mode: reset upload finalized as client cancellation");
    ok(wait_for(sub { !scalar body_files() }),
        "$mode: reset upload releases temporary files");
    $sid = $s->new_stream({ path => '/after-reset', body => 'GOOD' });
    is(status($s, $sid), 200, "$mode: connection usable after reset");
    $sid = $s->new_stream({ path => '/blocked', body => 'BAD BODY' });
    is(status($s, $sid), 403, "$mode: subsequent body still inspected");

    $s = Test::Nginx::HTTP2->new();
    $sid = $s->new_stream({
        method => 'POST', path => "/$mode/disconnect", body_more => 1
    });
    $s->h2_body('BAD BODY' . 'x' x 1016, { body_more => 1 });
    if ($mode eq 'file') {
        ok(wait_for(sub { scalar body_files() }),
            'body spills to disk before connection closes');
    }
    $other = $s->new_stream({ path => '/before-close', body => 'GOOD' });
    is(status($s, $other), 200, "$mode: partial body received before close");
    $s->{socket}->close();
    ok(wait_for(sub {
        $t->read_file('requests.log') =~ m{^/$mode/disconnect 499 ""$}m
    }), "$mode: connection-close upload finalized");
    ok(wait_for(sub { !scalar body_files() }),
        "$mode: closed connection releases temporary files");
    $s = Test::Nginx::HTTP2->new();
    $sid = $s->new_stream({ path => '/recovered', body => 'GOOD' });
    is(status($s, $sid), 200, "$mode: worker accepts new connection");
}

$t->stop();
unlike($t->read_file('upstream.log'), qr{/(memory|file)/(reset|disconnect)\s},
    'no interrupted body was forwarded upstream');
undef $t;

sub status {
    my ($s, $sid) = @_;
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    my ($frame) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid }
        @$frames;
    die "No response HEADERS for stream $sid" unless $frame;
    return $frame->{headers}->{':status'};
}

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
