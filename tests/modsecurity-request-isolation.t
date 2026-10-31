#!/usr/bin/perl

# Request isolation on HTTP/1.1, HTTP/2 and HTTP/3 connections.

use warnings;
use strict;

use IO::Socket::INET;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;
use Test::Nginx::HTTP3;

my $t = Test::Nginx->new()->has(qw/http http_v2 http_v3 proxy cryptx/)
    ->has_daemon('openssl')->plan(76);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}

http {
    %%TEST_GLOBALS_HTTP%%
    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
    log_format isolation '$connection $connection_requests $uri $status';

    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        http2 on;
        access_log %%TESTDIR%%/requests.log isolation;
        keepalive_timeout 30s;
        client_body_temp_path %%TESTDIR%%/body;
        add_header X-Connection $connection always;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_HEADERS:X-Seed "@streq yes" "id:101,phase:1,pass,nolog,setvar:tx.seed=1"
            SecRule TX:seed "@eq 1" "id:102,phase:2,deny,log,status:403"
            SecRule REQUEST_BODY "@contains BAD BODY" "id:103,phase:2,deny,log,status:403"
            SecRule ARGS:expected "@streq alpha" "id:104,phase:2,deny,log,status:403,chain"
                SecRule REQUEST_BODY "!@streq ALPHA" "t:none"
            SecRule ARGS:expected "@streq beta" "id:105,phase:2,deny,log,status:403,chain"
                SecRule REQUEST_BODY "!@streq BETA" "t:none"
        ';
        location / {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
        location /file/ {
            client_body_in_file_only clean;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
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

$t->run_daemon(\&echo_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->run();

foreach my $mode ('memory', 'file') {
    my $socket = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => port(8080), Proto => 'tcp'
    ) or die "Can't connect to nginx: $!\n";
    $socket->autoflush(1);
    my $connection;

    foreach my $case (
        ['alpha', 'ALPHA', 200, 0],
        ['blocked', 'BAD BODY', 403, 0],
        ['beta', 'BETA', 200, 0],
        ['seed', 'ALPHA', 403, 1],
        ['alpha', 'ALPHA', 200, 0]
    ) {
        my ($name, $body, $status, $seed) = @$case;
        my $path = "/$mode/$name?expected=$name";
        my ($headers, $received) = http1_request($socket, $path, $body, $seed);
        is($headers->{status}, $status, "HTTP/1.1 $mode: $name status");
        $connection = $headers->{'x-connection'} unless defined $connection;
        is($headers->{'x-connection'}, $connection,
            "HTTP/1.1 $mode: same connection for $name");
        is($received, $body, "HTTP/1.1 $mode: $name upstream body intact")
            if $status == 200;
    }
    close $socket;

    foreach my $protocol ('HTTP2', 'HTTP3') {
        my $class = "Test::Nginx::$protocol";
        my $s = $class->new();
        # For HTTP/3, $connection is per stream; $s retains the QUIC connection.
        my $path = "/$mode/alpha?expected=alpha";
        my $first = $s->new_stream({
            method => 'POST', path => $path, body_more => 1
        });
        send_body($s, $protocol, $first, 'AL', 1);

        my $other = $s->new_stream({
            method => 'POST', path => "/$mode/beta?expected=beta", body => 'BETA'
        });
        my ($headers, $received) = stream_response($s, $other);
        is($headers->{':status'}, 200, "$protocol $mode: parallel upload completes");
        is($received, 'BETA', "$protocol $mode: parallel body intact");
        my $connection = $headers->{'x-connection'};
        ok(defined $connection, "$protocol $mode: connection identifier present");

        my $blocked = $s->new_stream({
            method => 'POST', path => "/$mode/blocked", body => 'BAD BODY'
        });
        ($headers, $received) = stream_response($s, $blocked);
        is($headers->{':status'}, 403,
            "$protocol $mode: deny a stream while another upload is unfinished");
        is($headers->{'x-connection'}, $connection,
            "$protocol $mode: stream denial retains the connection")
            if $protocol eq 'HTTP2';

        # HTTP2->h2_body addresses last_stream; HTTP3 takes an explicit stream ID.
        my $last = $s->{last_stream};
        $s->{last_stream} = $first if $protocol eq 'HTTP2';
        send_body($s, $protocol, $first, 'PHA', 0);
        $s->{last_stream} = $last if $protocol eq 'HTTP2';
        ($headers, $received) = stream_response($s, $first);
        is($headers->{':status'}, 200, "$protocol $mode: suspended upload completes");
        is($received, 'ALPHA', "$protocol $mode: interleaved bodies stay separate");
        is($headers->{'x-connection'}, $connection,
            "$protocol $mode: interleaved uploads share a connection")
            if $protocol eq 'HTTP2';

        foreach my $case (
            ['blocked', 'BAD BODY', 403, 0],
            ['seed', 'ALPHA', 403, 1],
            ['beta', 'BETA', 200, 0]
        ) {
            my ($name, $body, $status, $seed) = @$case;
            my $request = {
                method => 'POST', path => "/$mode/$name?expected=$name", body => $body
            };
            if ($seed) {
                $request->{headers} = [
                    { name => ':method', value => 'POST' },
                    { name => ':scheme', value => $protocol eq 'HTTP3' ? 'https' : 'http' },
                    { name => ':path', value => $request->{path} },
                    { name => ':authority', value => 'localhost' },
                    { name => 'content-length', value => length($body) },
                    { name => 'x-seed', value => 'yes' }
                ];
            }
            my $sid = $s->new_stream($request);
            ($headers, $received) = stream_response($s, $sid);
            is($headers->{':status'}, $status, "$protocol $mode: $name status");
            is($headers->{'x-connection'}, $connection,
                "$protocol $mode: same connection after $name")
                if $protocol eq 'HTTP2';
            is($received, $body, "$protocol $mode: body and TX state not retained")
                if $status == 200;
        }
    }
}

$t->stop_daemons();

sub send_body {
    my ($s, $protocol, $sid, $body, $more) = @_;
    if ($protocol eq 'HTTP2') {
        $s->h2_body($body, { body_more => $more });
    } else {
        $s->h3_body($body, $sid, { body_more => $more });
    }
}

sub stream_response {
    my ($s, $sid) = @_;
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    my ($headers) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid } @$frames;
    die "No response HEADERS for stream $sid\n" unless $headers;
    my $body = join '', map { $_->{data} }
        grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
    return ($headers->{headers}, $body);
}

sub http1_request {
    my ($socket, $path, $body, $seed) = @_;
    local $SIG{ALRM} = sub { die "HTTP/1.1 response timed out\n" };
    alarm 8;
    print $socket "POST $path HTTP/1.1\r\nHost: localhost\r\n"
        . "Content-Length: " . length($body) . "\r\n"
        . ($seed ? "X-Seed: yes\r\n" : '') . "\r\n$body"
        or die "Can't send request: $!\n";
    my $line = <$socket>;
    die "Connection closed before response\n" unless defined $line;
    my ($status) = $line =~ m{^HTTP/1\.1 (\d{3}) };
    die "Invalid status line: $line" unless defined $status;
    my %headers = (status => $status);
    while (defined($line = <$socket>) && $line ne "\r\n") {
        my ($name, $value) = $line =~ /^([^:]+):\s*(.*?)\r\n$/;
        die "Invalid header: $line" unless defined $name;
        $headers{lc $name} = $value;
    }
    die "Missing header terminator\n" unless defined $line;
    die "Expected Content-Length\n" unless defined $headers{'content-length'};
    my $received = read_exact($socket, $headers{'content-length'});
    alarm 0;
    return (\%headers, $received);
}

sub read_exact {
    my ($socket, $length) = @_;
    my $body = '';
    while (length($body) < $length) {
        my $n = read($socket, my $part, $length - length($body));
        die "Incomplete body\n" unless defined $n && $n > 0;
        $body .= $part;
    }
    return $body;
}

sub echo_daemon {
    my $server = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => port(8081),
        Proto => 'tcp', Listen => 5, ReuseAddr => 1
    ) or die "Can't create upstream socket: $!\n";
    local $SIG{PIPE} = 'IGNORE';
    while (my $client = $server->accept()) {
        $client->autoflush(1);
        my $length = 0;
        while (my $line = <$client>) {
            last if $line eq "\r\n";
            $length = $1 if $line =~ /^Content-Length:\s*(\d+)/i;
        }
        my $body = read_exact($client, $length);
        print $client "HTTP/1.1 200 OK\r\nContent-Length: $length\r\n"
            . "Content-Type: text/plain\r\nConnection: close\r\n\r\n$body";
        close $client;
    }
}
