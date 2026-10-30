#!/usr/bin/perl

# Tests for ModSecurity-nginx request body operations over HTTP/3.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 proxy cryptx/)
	->has_daemon('openssl')->plan(51);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen 127.0.0.1:8081;
        location / {
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }
    }

    server {
        listen 127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name localhost;

        modsecurity on;
        add_header X-Body $request_body;
        add_header X-Body-File $request_body_file;
        add_header X-Protocol $server_protocol;

        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
        ';

        location /bodyaccess {
            modsecurity_rules '
                SecRule REQUEST_BODY "@contains BAD BODY" "id:11,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /exact {
            modsecurity_rules '
                SecRule REQUEST_BODY "!@streq VERY BAD BODY" "id:12,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;

            location /exact/file {
                client_body_in_file_only on;
                client_body_buffer_size 16;
                proxy_pass http://127.0.0.1:8081;
            }
        }

        location /nobodyaccess {
            modsecurity_rules '
                SecRequestBodyAccess Off
                SecRule REQUEST_BODY "@contains BAD BODY" "id:21,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /bodylimitreject {
            modsecurity_rules '
                SecRequestBodyLimit 128
                SecRequestBodyLimitAction Reject
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /bodylimitprocesspartial {
            modsecurity_rules '
                SecRequestBodyLimit 128
                SecRequestBodyLimitAction ProcessPartial
                SecRule REQUEST_BODY "@contains BAD BODY" "id:31,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /file {
            client_body_in_file_only on;
            client_body_buffer_size 16;
            modsecurity_rules '
                SecRule REQUEST_BODY "@contains BAD BODY" "id:41,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /form {
            modsecurity_rules '
                SecRule ARGS_POST:test "@streq BAD ARG" "id:51,phase:request,deny,log,status:403"
            ';
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
	or die "Can't create certificate: $!\n";

$t->run();

###############################################################################

foreach my $method ('GET', 'POST', 'PUT', 'DELETE') {
	my $headers = request({
		method => $method, path => '/bodyaccess', body => 'GOOD BODY'
	});
	is($headers->{':status'}, 200, "$method body access on, pass");
	is($headers->{'x-body'}, 'GOOD BODY', "$method nginx body preserved");

	is(request({ method => $method, path => '/bodyaccess',
		body => 'VERY BAD BODY' })->{':status'}, 403,
		"$method body access on, block");
	is(request({ method => $method, path => '/nobodyaccess',
		body => 'VERY BAD BODY' })->{':status'}, 200,
		"$method body access off, pass");
	is(request({ method => $method, path => '/bodylimitreject',
		body => 'BODY' x 32 })->{':status'}, 200,
		"$method body limit boundary, pass");
	is(request({ method => $method, path => '/bodylimitreject',
		body => 'BODY' x 32 . 'X' })->{':status'}, 403,
		"$method body limit exceeded by one byte, block");
	is(request({ method => $method, path => '/bodylimitprocesspartial',
		body => 'BODY' x 32 . 'BAD BODY' })->{':status'}, 200,
		"$method partial body, ignore data beyond limit");
	is(request({ method => $method, path => '/bodylimitprocesspartial',
		body => 'BODY' x 30 . 'BAD BODY' x 4 })->{':status'}, 403,
		"$method partial body, inspect data before limit");
}

my $headers = request({ path => '/bodyaccess' });
is($headers->{':status'}, 200, 'request without body');
is($headers->{'x-protocol'}, 'HTTP/3.0', 'requests use HTTP/3');
is(request({ path => '/bodyaccess', body => '' })->{':status'}, 200,
	'empty DATA frame');
is(request({ method => 'POST', path => '/exact', body => 'VERY BAD BODY',
	body_split => [4, 5] })->{':status'}, 200,
	'multiple DATA frames appended exactly once');
is(request({ method => 'POST', path => '/exact/file',
	body => 'VERY BAD BODY', body_split => [4, 5] })->{':status'}, 200,
	'file-buffered DATA frames are not appended again from disk');

my $s = Test::Nginx::HTTP3->new();
my $sid = $s->new_stream({
	method => 'POST', path => '/exact', body_more => 1
});
$s->h3_body('VERY BAD ', $sid, { body_more => 1 });
select undef, undef, undef, 0.1;
$s->h3_body('', $sid, { body_more => 1 });
$s->h3_body('BODY', $sid);
is(response_headers($s, $sid)->{':status'}, 200,
	'delayed DATA and empty frames appended exactly once');

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream({
	method => 'POST', path => '/bodyaccess', body_more => 1
});
$s->h3_body('VERY BAD ', $sid, { body_more => 1 });
select undef, undef, undef, 0.1;
$s->h3_body('BODY', $sid);
is(response_headers($s, $sid)->{':status'}, 403,
	'body rule matches across delayed DATA frames');

foreach my $case (
	['/bodylimitreject', 'BODY' x 32, 'X', 'BODY', 403,
		'deferred limit rejection survives additional DATA frames'],
	['/bodylimitprocesspartial', 'BODY' x 32, 'BAD ', 'BODY', 200,
		'partial processing ignores later DATA frames beyond the limit'],
	['/bodylimitprocesspartial', 'BODY' x 30 . 'BAD ', 'BODY', 'TAIL', 403,
		'partial processing inspects a match ending at the limit']
) {
	my ($path, $first, $second, $last, $status, $name) = @$case;
	$s = Test::Nginx::HTTP3->new();
	$sid = $s->new_stream({
		method => 'POST', path => $path, body_more => 1
	});
	$s->h3_body($first, $sid, { body_more => 1 });
	select undef, undef, undef, 0.1;
	$s->h3_body($second, $sid, { body_more => 1 });
	select undef, undef, undef, 0.1;
	$s->h3_body($last, $sid);
	is(response_headers($s, $sid)->{':status'}, $status, $name);
}

my $body = 'GOOD' x 300;
$headers = request({
	method => 'POST', path => '/file', body => $body
});
is($headers->{':status'}, 200, 'file-buffered request allowed');
is(read_body_file($headers->{'x-body-file'}), $body,
	'file-buffered body preserved for nginx');
is(request({ method => 'POST', path => '/file',
	body => $body . 'BAD BODY' })->{':status'}, 403,
	'file-buffered body inspected through its last bytes');

foreach my $value ('BAD ARG', 'GOOD ARG') {
	my $body = "test=$value";
	is(request({ headers => [
		{ name => ':method', value => 'POST' },
		{ name => ':scheme', value => 'https' },
		{ name => ':path', value => '/form' },
		{ name => ':authority', value => 'localhost' },
		{ name => 'content-type',
			value => 'application/x-www-form-urlencoded' },
		{ name => 'content-length', value => length($body) }
	], body => $body, body_split => [5] })->{':status'},
		$value eq 'BAD ARG' ? 403 : 200,
		"form body parsed after complete upload: $value");
}

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream({
	method => 'POST', path => '/exact', body_more => 1
});
$s->h3_body('VERY BAD ', $sid, { body_more => 1 });
my $other = $s->new_stream({ path => '/bodyaccess', body => 'GOOD BODY' });
is(response_headers($s, $other)->{':status'}, 200,
	'second stream completes while first upload is unfinished');
$s->h3_body('BODY', $sid);
is(response_headers($s, $sid)->{':status'}, 200,
	'interleaved streams do not mix request bodies');
$sid = $s->new_stream({ path => '/bodyaccess', body => 'BAD BODY' });
is(response_headers($s, $sid)->{':status'}, 403,
	'deny one stream on a reused connection');
$sid = $s->new_stream({ path => '/bodyaccess', body => 'GOOD BODY' });
is(response_headers($s, $sid)->{':status'}, 200,
	'connection remains usable after denying a stream');

###############################################################################

sub request {
	my ($request) = @_;
	my $s = Test::Nginx::HTTP3->new();
	my $sid = $s->new_stream($request);
	return response_headers($s, $sid);
}

sub response_headers {
	my ($s, $sid) = @_;
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid }
		@$frames;
	return $frame->{headers};
}

sub read_body_file {
	my ($path) = @_;
	return unless defined $path;
	open my $fh, '<', $path or die "Can't open $path: $!\n";
	local $/;
	return <$fh>;
}