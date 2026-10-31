#!/usr/bin/perl

# Incremental limits, phase ordering, and body preservation.

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;
use Test::Nginx::HTTP3;

my $t = Test::Nginx->new()->has(qw/http http_v2 http_v3 proxy mirror cryptx/)
    ->has_daemon('openssl')->plan(80);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        http2 on;
        client_body_buffer_size 128;
        client_body_temp_path %%TESTDIR%%/body;
        client_body_timeout 5s;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRequestBodyLimit 128
            SecRequestBodyLimitAction Reject
            SecRule REQUEST_BODY "@contains BAD BODY" "id:101,phase:2,deny,log,status:403,t:none"
        ';
        location /reject/ {
            proxy_pass http://127.0.0.1:8081;
        }
        location /file/ {
            client_body_in_file_only clean;
            proxy_pass http://127.0.0.1:8081;
        }
        location /partial/ {
            modsecurity_rules 'SecRequestBodyLimitAction ProcessPartial';
            proxy_pass http://127.0.0.1:8081;
        }
        location /phase/ {
            modsecurity_rules 'SecRequestBodyLimit 65536';
            proxy_pass http://127.0.0.1:8081;
        }
        location /prebuffer/ {
            modsecurity off;
            client_body_in_file_only clean;
            mirror /mirror;
            try_files /nonexistent-body-fixture @inspect;
        }
        location /mirror-read/ {
            modsecurity_rules 'SecRequestBodyLimit 65536';
            client_body_in_file_only clean;
            mirror /mirror;
            proxy_pass http://127.0.0.1:8081;
        }
        location = /mirror {
            internal;
            modsecurity off;
            return 204;
        }
        location @inspect {
            modsecurity_rules 'SecRequestBodyLimit 65536';
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF

$t->write_file('openssl.conf', <<'EOF');
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF
my $d = $t->testdir();
system('openssl req -x509 -new '
    . "-config $d/openssl.conf -subj /CN=localhost/ "
    . "-out $d/localhost.crt -keyout $d/localhost.key "
    . ">>$d/openssl.out 2>&1") == 0
    or die "Can't create certificate\n";
$t->write_file('upstream.log', '');
$t->run_daemon(\&echo_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081))
    or die "Upstream did not start\n";
$t->run();

foreach my $protocol ('HTTP1', 'HTTP2', 'HTTP3') {
    foreach my $mode ('reject', 'file') {
        my $path = "/$mode/$protocol";
        my ($s, $sid) = start_request($protocol, $path, 32768);
        send_body($protocol, $s, $sid, 'x' x 1024, 1);
        my ($status) = response($protocol, $s, $sid);
        is($status, 403, "$protocol $mode: limit rejected before EOF");
        ok(wait_for(sub { !scalar glob("$d/body/*") }),
            "$protocol $mode: rejection releases body files");
        close_client($protocol, $s);
        unlike($t->read_file('upstream.log'), qr{\Q$path\E },
            "$protocol $mode: incomplete denied upload never forwarded");
        if ($protocol ne 'HTTP1') {
            my $other = $s->new_stream({
                method => 'POST', path => "/phase/parallel-$protocol-$mode",
                body => 'GOOD'
            });
            my ($other_status, $body) = response($protocol, $s, $other);
            is($other_status, 200,
                "$protocol $mode: early rejection leaves connection usable");
            is($body, 'GOOD',
                "$protocol $mode: unrelated stream body unchanged");
        }
    }

    foreach my $case (
        ['beyond-limit', 'x' x 128 . 'BAD BODY' . 'z' x 2048, 200],
        ['within-limit', 'x' x 120 . 'BAD BODY' . 'z' x 2048, 403]
    ) {
        my ($name, $body, $expected) = @$case;
        my $path = "/partial/$protocol-$name";
        my ($s, $sid) = start_request($protocol, $path, length($body));
        my $remaining = $body;
        while (length($remaining)) {
            my $chunk = substr($remaining, 0, 64, '');
            send_body($protocol, $s, $sid, $chunk, length($remaining) ? 1 : 0);
        }
        my ($status, $received) = response($protocol, $s, $sid);
        is($status, $expected, "$protocol $name: partial inspection decision");
        if ($expected == 200) {
            is($received, $body, "$protocol: partial inspection preserves full upload");
        } else {
            unlike($t->read_file('upstream.log'), qr{\Q$path\E },
                "$protocol: inspected forbidden prefix never forwarded");
        }
        close_client($protocol, $s);
    }

    my $path = "/phase/$protocol";
    my ($s, $sid) = start_request($protocol, $path, 2048);
    send_body($protocol, $s, $sid, 'BAD BODY' . 'x' x 1016, 1);
    select undef, undef, undef, 0.1;
    SKIP: {
        skip 'requires nginx debug build', 1 unless $t->has_module('debug');
        like($t->read_file('error.log'),
            qr{modsecurity: appended request body buffer \d+ for "\Q$path\E"},
            "$protocol: body appended before EOF and file completion");
    }
    unlike($t->read_file('upstream.log'), qr{\Q$path\E },
        "$protocol: unfinished body never forwarded");
    unlike($t->read_file('error.log'),
        qr{Access denied.*\Q$path\E},
        "$protocol: phase 2 does not run before EOF");
    send_body($protocol, $s, $sid, 'x' x 1024, 0);
    my ($status) = response($protocol, $s, $sid);
    is($status, 403, "$protocol: phase 2 runs at EOF");
    close_client($protocol, $s);

    # A successful request after each rejection also checks worker recovery.
    ($s, $sid) = start_request($protocol, "/phase/recovered-$protocol", 4);
    send_body($protocol, $s, $sid, 'GOOD', 0);
    ($status, my $received) = response($protocol, $s, $sid);
    is($status, 200, "$protocol: worker accepts subsequent request");
    is($received, 'GOOD', "$protocol: subsequent body inspected once");
    close_client($protocol, $s);

    foreach my $mode ('prebuffer', 'mirror-read') {
        foreach my $case (
            ['allowed', 'GOOD' x 1024, 200],
            ['denied', 'BAD BODY' . 'x' x 4088, 403]
        ) {
            my ($name, $body, $expected) = @$case;
            $path = "/$mode/$protocol-$name";
            ($s, $sid) = start_request($protocol, $path, length($body));
            my $remaining = $body;
            while (length($remaining)) {
                my $chunk = substr($remaining, 0, 512, '');
                send_body($protocol, $s, $sid, $chunk, length($remaining) ? 1 : 0);
            }
            ($status, $received) = response($protocol, $s, $sid);
            is($status, $expected, "$protocol $mode: pre-buffered file $name");
            if ($expected == 200) {
                is($received, $body, "$protocol: pre-buffered file preserved");
            } else {
                unlike($t->read_file('upstream.log'), qr{\Q$path\E },
                    "$protocol: pre-buffered denied body never forwarded");
            }
            close_client($protocol, $s);
        }
    }
}
$t->stop();
undef $t;

sub start_request {
    my ($protocol, $path, $length) = @_;
    if ($protocol eq 'HTTP1') {
        my $s = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => port(8080), Proto => 'tcp'
        ) or die "Can't connect to nginx: $!\n";
        $s->autoflush(1);
        print $s "POST $path HTTP/1.1\r\nHost: localhost\r\n"
            . "Content-Length: $length\r\nConnection: close\r\n\r\n"
            or die "Can't send request headers: $!\n";
        return ($s, undef);
    }
    my $class = "Test::Nginx::$protocol";
    my $s = $class->new();
    my $sid = $s->new_stream({
        headers => [
            { name => ':method', value => 'POST' },
            { name => ':scheme',
                value => $protocol eq 'HTTP3' ? 'https' : 'http' },
            { name => ':path', value => $path },
            { name => ':authority', value => 'localhost' },
            { name => 'content-length', value => $length }
        ],
        body_more => 1
    });
    return ($s, $sid);
}

sub send_body {
    my ($protocol, $s, $sid, $body, $more) = @_;
    if ($protocol eq 'HTTP1') {
        print $s $body or die "Can't send body: $!\n";
    } elsif ($protocol eq 'HTTP2') {
        $s->h2_body($body, { body_more => $more });
    } else {
        $s->h3_body($body, $sid, { body_more => $more });
    }
}

sub response {
    my ($protocol, $s, $sid) = @_;
    if ($protocol eq 'HTTP1') {
        local $SIG{ALRM} = sub { die "Response timed out before EOF\n" };
        alarm 3;
        my $line = <$s>;
        die "Missing HTTP/1 response\n" unless defined $line;
        my ($status) = $line =~ m{^HTTP/1\.1 (\d{3}) };
        die "Invalid response: $line" unless defined $status;
        my $length;
        while (defined($line = <$s>) && $line ne "\r\n") {
            $length = $1 if $line =~ /^Content-Length:\s*(\d+)/i;
        }
        die "Missing response length\n" unless defined $length;
        my $body = '';
        while (length($body) < $length) {
            my $n = read($s, my $part, $length - length($body));
            die "Incomplete response\n" unless defined $n && $n > 0;
            $body .= $part;
        }
        alarm 0;
        return ($status, $body);
    }
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    my ($frame) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid } @$frames;
    die "Missing $protocol response before EOF\n" unless $frame;
    my $body = join '', map { $_->{data} }
        grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
    return ($frame->{headers}->{':status'}, $body);
}

sub close_client {
    my ($protocol, $s) = @_;
    close $s if $protocol eq 'HTTP1';
}

sub wait_for {
    my ($check) = @_;
    for (1 .. 50) {
        return 1 if $check->();
        select undef, undef, undef, 0.1;
    }
    return 0;
}

sub echo_daemon {
    my $server = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => port(8081),
        Proto => 'tcp', Listen => 5, ReuseAddr => 1
    ) or die "Can't create upstream socket: $!\n";
    local $SIG{PIPE} = 'IGNORE';
    while (my $client = $server->accept()) {
        $client->autoflush(1);
        my $request = <$client>;
        if (!defined $request) {
            close $client;
            next;
        }
        open my $log, '>>', "$d/upstream.log" or die "Can't open upstream log: $!\n";
        print $log $request or die "Can't log upstream request: $!\n";
        close $log;
        my $length;
        while (my $line = <$client>) {
            last if $line eq "\r\n";
            $length = $1 if $line =~ /^Content-Length:\s*(\d+)/i;
        }
        die "Missing upstream Content-Length\n" unless defined $length;
        my $body = '';
        while (length($body) < $length) {
            my $n = read($client, my $part, $length - length($body));
            die "Incomplete upstream body\n" unless defined $n && $n > 0;
            $body .= $part;
        }
        print $client "HTTP/1.1 200 OK\r\nContent-Length: $length\r\n"
            . "Connection: close\r\n\r\n$body" or die "Can't echo body: $!\n";
        close $client;
    }
}
