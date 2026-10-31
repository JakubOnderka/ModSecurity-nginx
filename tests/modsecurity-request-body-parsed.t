#!/usr/bin/perl

# Parsed arguments and upload metadata across protocols and body buffering modes.

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
    ->has_daemon('openssl')->plan(324);

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
            SecRule REQUEST_HEADERS:Content-Type "@beginsWith application/json" "id:101,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
            SecRule REQBODY_ERROR "!@eq 0" "id:102,phase:2,deny,log,status:400"
            SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:103,phase:2,deny,log,status:400"
            SecRule &ARGS:/^(json[.])?value$/ "@eq 0" "id:104,phase:2,deny,log,status:403"
            SecRule ARGS:/^(json[.])?value$/ "!@streq GOOD VALUE" "id:105,phase:2,deny,log,status:403,t:none"
            SecRule REQUEST_HEADERS:Content-Type "@beginsWith multipart/form-data" "id:106,phase:2,deny,log,status:403,chain"
                SecRule &FILES:upload "!@eq 1" "t:none"
            SecRule FILES:upload "!@streq fixture.bin" "id:107,phase:2,deny,log,status:403,t:none"
            SecRule FILES_SIZES:upload "!@eq 256" "id:108,phase:2,deny,log,status:403"
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

my $padding = 'x' x 2048;
my $form = 'application/x-www-form-urlencoded';
my $multipart = 'multipart/form-data; boundary=ParsedBodyBoundary';
my @cases = (
    ['form-decoded', $form, "padding=$padding&value=%47OOD+%56ALUE", 200],
    ['form-denied', $form, "padding=$padding&value=%42AD+VALUE", 403],
    ['form-duplicate', $form,
        "padding=$padding&value=GOOD+VALUE&value=BAD+VALUE", 403],
    ['json-decoded', 'application/json',
        '{"padding":"' . $padding . '","value":"GOOD\u0020VALUE"}', 200],
    ['json-denied', 'application/json',
        '{"padding":"' . $padding . '","value":"\u0042AD VALUE"}', 403],
    ['json-malformed', 'application/json',
        '{"padding":"' . $padding . '","value":"GOOD VALUE"', 400],
    ['multipart-upload', $multipart, multipart_body('GOOD VALUE', 1), 200],
    ['multipart-denied', $multipart, multipart_body('BAD VALUE', 1), 403],
    ['multipart-malformed', $multipart, multipart_body('GOOD VALUE', 0), 400],
    ['multipart-filename', $multipart,
        multipart_body('GOOD VALUE', 1, 'wrong.bin', 256), 403],
    ['multipart-size', $multipart,
        multipart_body('GOOD VALUE', 1, 'fixture.bin', 255), 403]
);

foreach my $protocol ('HTTP1', 'HTTP2', 'HTTP3') {
    foreach my $mode ('memory', 'spill', 'file') {
        foreach my $case (@cases) {
            my ($name, $type, $body, $expected) = @$case;
            my $id = "$protocol-$mode-$name";
            my ($headers, $received) = request(
                $protocol, "/$mode/$id", $type, $body);
            is($headers->{status}, $expected, "$id: parsed body decision");
            is($headers->{'x-body-storage'},
                $mode eq 'memory' ? 'memory' : 'file',
                "$id: requested buffering path exercised");
            if ($expected == 200) {
                is($t->read_file("$id.body"), $body,
                    "$id: upstream receives unchanged encoded body");
                is($received, $body, "$id: response echoes exact body");
            } else {
                ok(!-e "$d/$id.body", "$id: denied body never forwarded");
            }
        }
    }
}
$t->stop_daemons();
undef $t;

sub multipart_body {
    my ($value, $complete, $filename, $size) = @_;
    $filename = 'fixture.bin' unless defined $filename;
    $size = 256 unless defined $size;
    my $body = "--ParsedBodyBoundary\r\n"
        . "Content-Disposition: form-data; name=\"value\"\r\n\r\n$value\r\n"
        . "--ParsedBodyBoundary\r\n"
        . "Content-Disposition: form-data; name=\"padding\"\r\n\r\n"
        . 'x' x 2048 . "\r\n--ParsedBodyBoundary\r\n"
        . "Content-Disposition: form-data; name=\"upload\"; filename=\"$filename\"\r\n"
        . "Content-Type: application/octet-stream\r\n\r\n"
        . pack('C*', 0 .. $size - 1) . "\r\n";
    $body .= "--ParsedBodyBoundary--\r\n" if $complete;
    return $body;
}

sub request {
    my ($protocol, $path, $type, $body) = @_;
    if ($protocol eq 'HTTP1') {
        my $socket = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => port(8080), Proto => 'tcp'
        ) or die "Can't connect to nginx: $!\n";
        $socket->autoflush(1);
        print $socket "POST $path HTTP/1.1\r\nHost: localhost\r\n"
            . "Content-Type: $type\r\nContent-Length: " . length($body)
            . "\r\nConnection: close\r\n\r\n"
            or die "Can't send request headers: $!\n";
        while (length($body)) {
            print $socket substr($body, 0, 17, '')
                or die "Can't send request body: $!\n";
        }
        local $SIG{ALRM} = sub { die "HTTP/1 response timed out\n" };
        alarm 8;
        my $response = '';
        while (1) {
            my $n = sysread($socket, my $part, 8192);
            die "Can't read response: $!\n" unless defined $n;
            last unless $n;
            $response .= $part;
        }
        alarm 0;
        close $socket;
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
            { name => 'content-type', value => $type },
            { name => 'content-length', value => length($body) }
        ],
        body_more => 1
    });
    while (length($body)) {
        my $chunk = substr($body, 0, 17, '');
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
        my $body = '';
        while (length($body) < $length) {
            my $n = read($client, my $part, $length - length($body));
            die "Incomplete upstream body\n" unless defined $n && $n > 0;
            $body .= $part;
        }
        $t->write_file("$id.body", $body);
        print $client "HTTP/1.1 200 OK\r\nContent-Length: $length\r\n"
            . "Content-Type: application/octet-stream\r\n"
            . "Connection: close\r\n\r\n$body"
            or die "Can't echo upstream body: $!\n";
        close $client;
    }
}