#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void
ngx_http_unbuffered_test_body_handler(ngx_http_request_t *r)
{
    r->main->count--;
}


static ngx_int_t
ngx_http_unbuffered_test_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    static ngx_str_t uri = ngx_string("/unbuffered-test");
    static ngx_str_t flag_uri = ngx_string("/unbuffered-flag");
    static ngx_str_t discarded_uri = ngx_string("/discarded-test");

    if (r->uri.len == discarded_uri.len
        && ngx_strncmp(r->uri.data, discarded_uri.data, discarded_uri.len) == 0)
    {
        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            return rc;
        }
        return NGX_DECLINED;
    }

    if (r->uri.len == flag_uri.len
        && ngx_strncmp(r->uri.data, flag_uri.data, flag_uri.len) == 0)
    {
        r->request_body_no_buffering = 1;
        return NGX_DECLINED;
    }

    if (r->uri.len != uri.len
        || ngx_strncmp(r->uri.data, uri.data, uri.len) != 0)
    {
        return NGX_DECLINED;
    }

    r->request_body_no_buffering = 1;
    rc = ngx_http_read_client_request_body(r,
                                          ngx_http_unbuffered_test_body_handler);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_unbuffered_test_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *handler;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    handler = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_unbuffered_test_handler;
    return NGX_OK;
}


static ngx_http_module_t ngx_http_unbuffered_test_ctx = {
    NULL, ngx_http_unbuffered_test_init,
    NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_modsecurity_unbuffered_test_module = {
    NGX_MODULE_V1,
    &ngx_http_unbuffered_test_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};