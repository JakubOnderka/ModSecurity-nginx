#!/usr/bin/perl

# Tests for response body processing when nginx sends empty buffers.

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http proxy/);
$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        default_type text/plain;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecRule RESPONSE_BODY "@streq BAD BODY" "id:101,phase:4,log,auditlog,pass"
            SecRule REQUEST_FILENAME "@streq /empty" "id:102,phase:4,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLog %%TESTDIR%%/audit.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';
        location /proxy {
            proxy_pass http://127.0.0.1:8081/;
            proxy_buffering off;
        }
    }
    server {
        listen 127.0.0.1:8081;
        return 200 "BAD BODY";
    }
}
EOF
$t->write_file('empty', '');
$t->run()->plan(4);

# Unbuffered proxying sends the response data and the final marker separately.
like(http_get('/proxy'), qr/BAD BODY/, 'response data before empty last buffer');
like(http_get('/empty'), qr/^HTTP.*200/, 'empty static response');

my $audit = do {
    local $/;
    open my $fh, '<', $t->testdir() . '/audit.txt'
        or die "could not open audit log: $!";
    <$fh>;
};

like($audit, qr/\[id "101"\]/, 'phase 4 inspects data before empty last buffer');
like($audit, qr/\[id "102"\]/, 'phase 4 runs for empty response');
