/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <ngx_config.h>

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


static ngx_inline void
ngx_http_modsecurity_add_response_header(ngx_http_modsecurity_ctx_t *ctx, ngx_str_t *name, ngx_str_t *value)
{
    /* This helper returns void; callers do not need to check a status code. msc_add_n_response_header always return 1. */
    msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name->data,
        name->len,
        (const unsigned char *) value->data,
        value->len);
}


static void
ngx_http_modsecurity_resolv_header_server(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    static char ngx_http_server_full_string[] = NGINX_VER;
    static char ngx_http_server_string[] = "nginx";

    ngx_http_core_loc_conf_t *clcf = NULL;
    ngx_str_t value;

    if (r->headers_out.server != NULL) {
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->server_tokens) {
        value.data = (u_char *)ngx_http_server_full_string;
        value.len = sizeof(ngx_http_server_full_string) - 1;
    } else {
        value.data = (u_char *)ngx_http_server_string;
        value.len = sizeof(ngx_http_server_string) - 1;
    }

    ngx_http_modsecurity_add_response_header(ctx, &name, &value);
}


static void
ngx_http_modsecurity_resolv_header_date(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    ngx_str_t date;

    if (r->headers_out.date != NULL) {
        return;
    }

    date.data = ngx_cached_http_time.data;
    date.len = ngx_cached_http_time.len;

    ngx_http_modsecurity_add_response_header(ctx, &name, &date);
}


static void
ngx_http_modsecurity_resolv_header_content_length(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    ngx_str_t value;
    char buf[NGX_OFF_T_LEN];

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        value.len = (int)(ngx_sprintf((u_char *)buf, "%O", r->headers_out.content_length_n) - (u_char *)buf);
        value.data = (unsigned char *)buf;

        ngx_http_modsecurity_add_response_header(ctx, &name, &value);
    }
}


static void
ngx_http_modsecurity_resolv_header_content_type(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    if (r->headers_out.content_type.len > 0) {
        ngx_http_modsecurity_add_response_header(ctx, &name, &r->headers_out.content_type);
    }
}


static void
ngx_http_modsecurity_resolv_header_last_modified(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    u_char buf[sizeof("Mon, 28 Sep 1970 06:00:00 GMT")], *p;
    ngx_str_t value;

    if (r->headers_out.last_modified_time == -1) {
        return;
    }

    p = ngx_http_time(buf, r->headers_out.last_modified_time);

    value.data = buf;
    value.len = (int)(p-buf);

    ngx_http_modsecurity_add_response_header(ctx, &name, &value);
}

static ngx_str_t ngx_http_modsecurity_connection_close = ngx_string("close");
static ngx_str_t ngx_http_modsecurity_connection_upgrade = ngx_string("upgrade");
static ngx_str_t ngx_http_modsecurity_connection_keepalive = ngx_string("keep-alive");


static void
ngx_http_modsecurity_resolv_header_connection(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
    ngx_http_core_loc_conf_t *clcf = NULL;
    ngx_str_t connection;
    ngx_str_t value;

#ifdef NGX_HTTP_VERSION_20
    if (r->http_version == NGX_HTTP_VERSION_20) {
        return;
    }
#endif
#ifdef NGX_HTTP_VERSION_30
    if (r->http_version == NGX_HTTP_VERSION_30) {
        return;
    }
#endif

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        connection = ngx_http_modsecurity_connection_upgrade;
    } else if (r->keepalive) {
        connection = ngx_http_modsecurity_connection_keepalive;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (clcf->keepalive_header)
        {
            u_char buf[sizeof("timeout=") - 1 + NGX_TIME_T_LEN];
            ngx_str_t name2 = ngx_string("Keep-Alive");

            value.data = buf;
            value.len = ngx_sprintf(buf, "timeout=%T",
                clcf->keepalive_header) - buf;

            ngx_http_modsecurity_add_response_header(ctx, &name2, &value);
        }
    } else {
        connection = ngx_http_modsecurity_connection_close;
    }

    ngx_http_modsecurity_add_response_header(ctx, &name, &connection);
}

static void
ngx_http_modsecurity_resolv_header_transfer_encoding(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
#ifdef NGX_HTTP_VERSION_20
    if (r->http_version == NGX_HTTP_VERSION_20) {
        return;
    }
#endif
#ifdef NGX_HTTP_VERSION_30
    if (r->http_version == NGX_HTTP_VERSION_30) {
        return;
    }
#endif

    if (r->chunked) {
        ngx_str_t value = ngx_string("chunked");
        ngx_http_modsecurity_add_response_header(ctx, &name, &value);
    }
}

static void
ngx_http_modsecurity_resolv_header_vary(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_str_t name)
{
#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t *clcf = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (r->gzip_vary && clcf->gzip_vary) {
        ngx_str_t value = ngx_string("Accept-Encoding");

        ngx_http_modsecurity_add_response_header(ctx, &name, &value);
    }
#endif
}

ngx_int_t
ngx_http_modsecurity_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;

    return NGX_OK;
}


ngx_int_t
ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    int ret = 0;
    ngx_uint_t status;
    char *http_response_ver;
    ngx_pool_t *old_pool;


/* XXX: if NOT_MODIFIED, do we need to process it at all?  see xslt_header_filter() */

    ctx = ngx_http_modsecurity_get_module_ctx(r);

    dd("header filter, recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ModSecurity not enabled or an error occured");
        return ngx_http_next_header_filter(r);
    }

    if (ctx->intervention_triggered) {
        return ngx_http_next_header_filter(r);
    }

/* XXX: can it happen ?  already processed i mean */
/* XXX: check behaviour on 'ModSecurity off' */

    if (ctx->processed)
    {
        /*
         * FIXME: verify if this request is already processed.
         */
        dd("Already processed... going to the next header...");
        return ngx_http_next_header_filter(r);
    }

    /*
     * Lets ask nginx to keep the response body in memory
     *
     * FIXME: I don't see a reason to keep it `1' when SecResponseBody is disabled.
     */
    r->filter_need_in_memory = 1;

    ctx->processed = 1;
    /*
     * Assuming ModSecurity module is running immediately before the
     * ngx_http_header_filter, we will be able to populate ModSecurity with
     * headers from the headers_out structure.
     *
     * As ngx_http_header_filter place a direct call to the
     * ngx_http_write_filter_module, we cannot hook between those two. In order
     * to enumerate all headers, we first look at the headers_out structure,
     * and later we look into the ngx_list_part_t. The ngx_list_part_t must be
     * checked. Other module(s) in the chain may added some content to it.
     */

 #define NGX_HTTP_MODSECURITY_RESOLV_HEADER(header_name, header) \
    ngx_http_modsecurity_resolv_header_##header_name(r, ctx, (ngx_str_t)ngx_string(header))

    NGX_HTTP_MODSECURITY_RESOLV_HEADER(server, "Server");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(date, "Date");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(content_length, "Content-Length");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(content_type, "Content-Type");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(last_modified, "Last-Modified");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(connection, "Connection");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(transfer_encoding, "Transfer-Encoding");
    NGX_HTTP_MODSECURITY_RESOLV_HEADER(vary, "Vary");

#undef NGX_HTTP_MODSECURITY_RESOLV_HEADER

    for (i = 0 ;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

        ngx_http_modsecurity_add_response_header(ctx, &data[i].key, &data[i].value);
    }

    /* prepare extra paramters for msc_process_response_headers() */
    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    /*
     * NGINX always sends HTTP response with HTTP/1.1, except cases when
     * HTTP V2 module is enabled, and request has been posted with HTTP/2.0
     * or when using HTTP V3
     */
    switch (r->http_version) {
#ifdef NGX_HTTP_VERSION_30
        case NGX_HTTP_VERSION_30 :
            http_response_ver = "HTTP 3.0";
            break;
#endif
#ifdef NGX_HTTP_VERSION_20
        case NGX_HTTP_VERSION_20 :
            http_response_ver = "HTTP 2.0";
            break;
#endif
        default:
            http_response_ver = "HTTP 1.1";
            break;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_response_headers(ctx->modsec_transaction, status, http_response_ver);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (r->error_page) {
        return ngx_http_next_header_filter(r);
    }
    if (ret > 0) {
        return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, ret);
    }

    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        /*
         * The connection turns into a raw tunnel (e.g. WebSocket); there
         * will be no more HTTP traffic, so release the transaction now.
         */
        ngx_http_modsecurity_log_handler(r);
        ngx_http_modsecurity_cleanup(ctx);
        return ngx_http_next_header_filter(r);
    }

    /*
     * Proxies will not like this... but it is necessary to unset
     * the content length in order to manipulate the content of
     * response body in ModSecurity.
     *
     * This header may arrive at the client before ModSecurity had
     * a change to make any modification. That is why it is necessary
     * to set this to -1 here.
     *
     * We need to have some kind of flag the decide if ModSecurity
     * will make a modification or not. If not, keep the content and
     * make the proxy servers happy.
     *
     */

    /*
     * The line below is commented to make the spdy test to work
     */
     //r->headers_out.content_length_n = -1;

    return ngx_http_next_header_filter(r);
}
