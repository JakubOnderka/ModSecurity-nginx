#!/usr/bin/perl

# Tests for ModSecurity over the http proxy module with protocol switching
# (HTTP 101, e.g. WebSocket). The transaction is released on 101, and the
# tunnel must keep working afterwards.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(9);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule ARGS "@streq block" "id:1,phase:1,status:403,deny"
            ';
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 5s;
        }

        location /fallback {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule ARGS "@streq block" "id:1,phase:1,status:403,deny"
            ';
            error_page 403 = @websocket;
                error_page 404 = @websocket;
        }

        location @websocket {
            rewrite ^ /ws break;
            proxy_pass http://127.0.0.1:8081;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 5s;
        }
    }
}

EOF

$t->run_daemon(\&ws_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

my $s = upgrade('/ws');
like(read_headers($s), qr/^HTTP\/1\.1 101/, 'switching protocols');

print $s "hello\n";
is(read_line($s), "echo:hello\n", 'tunnel echo 1');

print $s "world\n";
is(read_line($s), "echo:world\n", 'tunnel echo 2');

# data pushed by the backend without a client request
is(read_line($s), "server-push\n", 'backend push');
close $s;

# repeated upgrades on the same worker
$s = upgrade('/ws2');
like(read_headers($s), qr/^HTTP\/1\.1 101/, 'switching protocols again');
close $s;

# a ModSecurity denial can be handled by an error-page upgrade
$s = upgrade('/fallback?a=block');
like(read_headers($s), qr/^HTTP\/1\.1 101/, 'error-page fallback after intervention');
close $s;

$s = upgrade('/fallback');
like(read_headers($s), qr/^HTTP\/1\.1 101/, 'error-page fallback after 404');
close $s;

# rules still apply for requests which do not switch protocols
like(http_get('/ws?a=block'), qr/^HTTP\/1\.\d 403/, 'blocked request');

$t->stop();

unlike($t->read_file('error.log'), qr/\[(alert|emerg)\]/, 'no errors');

###############################################################################

sub upgrade {
	my ($uri) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect: $!\n";
	$s->autoflush(1);

	print $s "GET $uri HTTP/1.1\r\n"
		. "Host: localhost\r\n"
		. "Upgrade: websocket\r\n"
		. "Connection: Upgrade\r\n\r\n";
	return $s;
}

sub read_headers {
	my ($s) = @_;
	my $h = '';

	local $SIG{ALRM} = sub { die "timeout\n" };
	alarm(5);
	eval {
		while (<$s>) {
			$h .= $_;
			last if /^\x0d?\x0a$/;
		}
	};
	alarm(0);
	return $h;
}

sub read_line {
	my ($s) = @_;
	my $l = '';

	local $SIG{ALRM} = sub { die "timeout\n" };
	alarm(5);
	eval { $l = <$s> };
	alarm(0);
	return defined $l ? $l : '';
}

sub ws_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a$/);
		}

		my $uri = $headers =~ /^\S+\s+(\S+)\s+HTTP/i ? $1 : '';

		if ($uri =~ m{^/ws}) {
			print $client "HTTP/1.1 101 Switching Protocols\r\n"
				. "Upgrade: websocket\r\n"
				. "Connection: Upgrade\r\n\r\n";

			if ($uri eq '/ws') {
				my $n = 0;
				while (my $line = <$client>) {
					print $client "echo:$line";
					last if ++$n == 2;
				}
				select undef, undef, undef, 0.1;
				print $client "server-push\n";
			}
		} else {
			print $client "HTTP/1.1 404 Not Found\r\n"
				. "Connection: close\r\n\r\n";
		}

		close $client;
	}
}

###############################################################################
