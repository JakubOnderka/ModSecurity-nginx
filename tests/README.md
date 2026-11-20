# Tests

Those are nginx test files. You can copy those files into yours nginx test
tree, to perform the tests using the "prove" utility.

For more information about those tests, read the subsection "Testing your
patch" on the project's README file.

For more about nginx tests, check their repository:
http://hg.nginx.org/nginx-tests/

The request-body unbuffered integration test, including its discarded-body
regression case, requires the test-only module in this directory. Add
`--add-module=/path/to/ModSecurity-nginx/tests` when
building the Nginx test binary, in addition to the connector module. Do not
include this test module in production builds.