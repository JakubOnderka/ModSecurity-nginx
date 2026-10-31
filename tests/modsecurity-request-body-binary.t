#!/usr/bin/perl

# Binary request bodies in memory and across 8192-byte file reads.

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
    ->has_daemon('openssl')->plan(225);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}

http {
    %%TEST_GLOBALS_HTTP%%
    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;
    map $request_body_file $body_storage {
        "" memory;
        default file;
    }

    server {
        listen 127.0.0.1:8080;
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        http2 on;
        client_body_temp_path %%TESTDIR%%/body;
        add_header X-Body-Storage $body_storage always;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRequestBodyLimit 65536
            SecRule REQUEST_BODY "@contains BAD BODY" "id:101,phase:2,deny,log,status:403,t:none"
        ';

        location /memory/ {
            client_body_buffer_size 64k;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
        location /spill/ {
            client_body_buffer_size 128;
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
$t->waitforsocket('127.0.0.1:' . port(8081))
    or die "Upstream did not start\n";
$t->run();

my @cases = map { ["allowed-$_", binary_body($_), 200] }
    (8191, 8192, 8193, 16385);
foreach my $case (
    ['after-nul', 8193, 64],
    ['first-boundary', 8200, 8190],
    ['second-boundary', 16400, 16382]
) {
    my ($name, $length, $offset) = @$case;
    my $body = binary_body($length);
    substr($body, $offset, 8, 'BAD BODY');
    push @cases, [$name, $body, 403];
}

foreach my $protocol ('HTTP1', 'HTTP2', 'HTTP3') {
    foreach my $mode ('memory', 'spill', 'file') {
        foreach my $case (@cases) {
            my ($name, $body, $expected) = @$case;
            my $id = "$protocol-$mode-$name";
            my ($headers, $received) = request(
                $protocol, "/$mode/$id", $body);
            is($headers->{status}, $expected, "$id: status");
            is($headers->{'x-body-storage'},
                $mode eq 'memory' ? 'memory' : 'file',
                "$id: requested buffering path exercised");
            if ($expected == 200) {
                is($t->read_file("$id.body"), $body,
                    "$id: upstream body byte-for-byte intact");
                is($received, $body, "$id: echoed binary body intact");
            } else {
                ok(!-e "$d/$id.body", "$id: denied body never forwarded");
            }
        }
    }
}

$t->stop_daemons();
undef $t;

sub binary_body {
    my ($length) = @_;
    my $bytes = pack('C*', 0 .. 255);
    return substr($bytes x (int($length / 256) + 1), 0, $length);
}

sub request {
    my ($protocol, $path, $body) = @_;
    if ($protocol eq 'HTTP1') {
        my $response = http("POST $path HTTP/1.1\r\n"
            . "Host: localhost\r\nContent-Type: application/octet-stream\r\n"
            . "Content-Length: " . length($body)
            . "\r\nConnection: close\r\n\r\n$body");
        my ($head, $received) = split /\r\n\r\n/, $response, 2;
        die "Incomplete HTTP/1 response\n" unless defined $received;
        my ($status) = $head =~ m{^HTTP/1\.1 (\d{3}) };
        die "Invalid HTTP/1 status\n" unless defined $status;
        my %headers = (status => $status);
        while ($head =~ /^([^:\r\n]+):[ \t]*(.*?)\r?$/mg) {
            $headers{lc $1} = $2;
        }
        return (\%headers, $received);
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
            { name => 'content-type', value => 'application/octet-stream' },
            { name => 'content-length', value => length($body) }
        ],
        body_more => 1
    });
    # Keep QUIC datagrams below the MTU, independently of file-read boundaries.
    while (length($body)) {
        my $chunk = substr($body, 0, 1000, '');
        my $extra = { body_more => length($body) ? 1 : 0 };
        if ($protocol eq 'HTTP2') {
            $s->h2_body($chunk, $extra);
        } else {
            $s->h3_body($chunk, $sid, $extra);
        }
    }
    my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
    my ($frame) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid }
        @$frames;
    die "No response HEADERS for $protocol stream $sid\n" unless $frame;
    my $received = join '', map { $_->{data} }
        grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
    return ({ %{$frame->{headers}}, status => $frame->{headers}->{':status'} },
        $received);
}

sub read_exact {
    my ($socket, $length) = @_;
    my $body = '';
    while (length($body) < $length) {
        my $n = read($socket, my $part, $length - length($body));
        die "Incomplete upstream body\n" unless defined $n && $n > 0;
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
        my $request = <$client>;
        if (!defined $request) {
            close $client;
            next;
        }
        my ($id) = $request =~ m{^POST /(?:memory|spill|file)/([\w-]+) };
        die "Invalid upstream request: $request" unless defined $id;
        my $length;
        while (my $line = <$client>) {
            last if $line eq "\r\n";
            $length = $1 if $line =~ /^Content-Length:\s*(\d+)/i;
        }
        die "Missing upstream Content-Length\n" unless defined $length;
        my $body = read_exact($client, $length);
        $t->write_file("$id.body", $body);
        print $client "HTTP/1.1 200 OK\r\nContent-Length: $length\r\n"
            . "Content-Type: application/octet-stream\r\n"
            . "Connection: close\r\n\r\n$body"
            or die "Can't echo upstream body: $!\n";
        close $client;
    }
}