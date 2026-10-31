#!/usr/bin/perl

# Tests for ModSecurity response body operations over HTTP/2.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/)->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        http2 on;
        server_name localhost;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecRule RESPONSE_BODY "@contains BAD BODY" "id:11,phase:response,deny,log,status:403"
        ';

        location / {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->waitforsocket('127.0.0.1:' . port(8081));
$t->run();
$t->todo_alerts();

###############################################################################

my ($headers, $body) = request('/good');
is($headers->{':status'}, 200, 'allowed response status is preserved');
is($body, 'GOOD BODY', 'allowed response body is preserved');

TODO: {
local $TODO = 'response-body blocking is not yet supported';
($headers, $body) = request('/bad');
ok($headers->{':status'} == 403 && $body !~ /BAD BODY/,
	'matching response body is blocked without leaking the body');
($headers, $body) = request('/split');
ok($headers->{':status'} == 403 && $body !~ /BAD BODY/,
	'response rule matches across upstream writes without leaking the body');
}

($headers, $body) = request('/head', 'HEAD');
is($headers->{':status'}, 200, 'HEAD response status is preserved');
is($body, '', 'HEAD response does not emit a response body');
($headers, $body) = request('/empty');
is($headers->{':status'}, 204, 'bodyless upstream response is preserved');
($headers, $body) = request('/not-modified');
is($headers->{':status'}, 304, '304 response is preserved');
($headers, $body) = request('/large');
is(length($body), 8192, 'large allowed response body is preserved');
($headers, $body) = request('/range', 'GET', 1);
ok($headers->{':status'} == 206 && $body eq 'GOOD',
	'range response is preserved');

###############################################################################

sub request {
	my ($path, $method, $range) = @_;
	my $s = Test::Nginx::HTTP2->new();
	my $stream = { path => $path, method => $method || 'GET' };
	$stream->{headers} = [
		{ name => ':method', value => $method || 'GET' },
		{ name => ':scheme', value => 'http' },
		{ name => ':path', value => $path },
		{ name => ':authority', value => 'localhost' },
		{ name => 'range', value => 'bytes=0-3' }
	] if $range;
	my $sid = $s->new_stream($stream);
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid }
		@$frames;
	my $body = join '', map { $_->{data} // '' }
		grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$frames;
	return ($frame->{headers}, $body);
}

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	) or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $request = '';
		while (my $line = <$client>) {
			last if $line =~ /^\x0d?\x0a$/;
			$request .= $line;
		}
		if ($request eq '') {
			close $client;
			next;
		}
		my ($uri) = $request =~ /^\S+\s+(\S+)/;

		if ($uri eq '/empty') {
			print $client "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
		} elsif ($uri eq '/not-modified') {
			print $client "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
		} elsif ($uri eq '/range' && $request =~ /^range: bytes=0-3\r?$/mi) {
			print $client "HTTP/1.1 206 Partial Content\r\n"
				. "Content-Type: text/plain\r\nContent-Range: bytes 0-3/9\r\n"
				. "Content-Length: 4\r\nConnection: close\r\n\r\nGOOD";
		} else {
			my $body = $uri eq '/good' ? 'GOOD BODY'
				: $uri eq '/large' ? 'G' x 8192 : 'BAD BODY';
			print $client "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
				. "Content-Length: " . length($body)
				. "\r\nConnection: close\r\n\r\n";
			if ($uri eq '/split') {
				print $client 'BAD ';
				select undef, undef, undef, 0.1;
				print $client 'BODY';
			} elsif ($request !~ /^HEAD\b/) {
				print $client $body;
			}
		}

		close $client;
	}
}

###############################################################################
