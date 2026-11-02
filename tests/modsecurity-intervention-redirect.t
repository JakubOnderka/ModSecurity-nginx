#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (redirect interventions).

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

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format modsecurity_status '$uri $status $modsecurity_status';
    access_log %%TESTDIR%%/status.log modsecurity_status;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        modsecurity on;

        location /redirect {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq redirect" "id:101,phase:1,log,status:302,redirect:http://www.modsecurity.org/"
                SecRule ARGS "@streq redirect301" "id:103,phase:1,log,status:301,redirect:http://www.modsecurity.org/"
            ';
        }

        location /deny {
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:104,phase:1,deny,status:403"
            ';
        }

        location /native-redirect {
            modsecurity off;
            return 302 http://www.modsecurity.org/;
        }

        location /respredirect {
            default_type text/plain;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABH
                SecAuditLogType Serial
                SecAuditLog %%TESTDIR%%/audit-respredirect.txt
                SecRule RESPONSE_BODY "@contains MARKER" "id:102,phase:4,log,auditlog,status:302,redirect:http://www.modsecurity.org/"
            ';
        }
    }
}
EOF

$t->write_file("/redirect", "should be redirected before this.");
$t->write_file("/respredirect", "response body with a MARKER in it.");

$t->run();

# the phase 4 intervention below happens after the response headers have
# already been sent, so nginx finalizes the request with an alert
$t->todo_alerts();

$t->plan(15);

###############################################################################

my $r = http_get('/redirect?what=redirect');

like($r, qr!^HTTP/1.1 302!, 'phase 1 redirect - status');
like($r, qr!^Location: http://www\.modsecurity\.org/\x0d?$!m, 'phase 1 redirect - location');

# headers are already sent at this point, the redirection cannot be
# performed; the only requirement here is that nginx stays alive
http_get('/respredirect');

like(http_get('/redirect?what=redirect'), qr!^HTTP/1.1 302!, 'phase 1 redirect - still serving after phase 4 intervention');

my $audit = '';
$audit = $t->read_file('audit-respredirect.txt')
    if -e $t->testdir() . '/audit-respredirect.txt';

like($audit, qr/\[id "102"\]/, 'phase 4 redirect - audit log');

$r = http_get('/redirect?what=redirect301');
like($r, qr!^HTTP/1.1 301!, 'phase 1 permanent redirect - status');
like($r, qr!^Location: http://www\.modsecurity\.org/\x0d?$!m,
    'phase 1 permanent redirect - location');
like(http_get('/deny'), qr!^HTTP/1.1 403!, 'deny - status');
like(http_get('/redirect?what=allowed'), qr!^HTTP/1.1 200!, 'allowed - status');
like(http_get('/native-redirect'), qr!^HTTP/1.1 302!, 'native redirect - status');

$t->stop();
my $status_log = $t->read_file('status.log');
my @redirects = $status_log =~ m!^/redirect 302 302$!mg;
is(scalar @redirects, 2, 'modsecurity_status records repeated redirects');
like($status_log, qr!^/redirect 301 301$!m,
    'modsecurity_status records permanent redirects');
like($status_log, qr!^/respredirect \d{3} 302$!m,
    'modsecurity_status records redirects even after headers are sent');
like($status_log, qr!^/deny 403 403$!m,
    'modsecurity_status still records denials');
like($status_log, qr!^/redirect 200 -$!m,
    'modsecurity_status remains unset without an intervention');
like($status_log, qr!^/native-redirect 302 -$!m,
    'modsecurity_status remains unset when ModSecurity is disabled');
