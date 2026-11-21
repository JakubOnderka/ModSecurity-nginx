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

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

ngx_int_t
ngx_http_modsecurity_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;

    return NGX_OK;
}

ngx_int_t
ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                   *buf;
    ngx_chain_t                 *chain;
    ngx_http_modsecurity_ctx_t  *ctx;
    ngx_uint_t                   last_buf = 0;
    int                          ret;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    dd("body filter, recovering ctx: %p", ctx);

    if (ctx == NULL) {
        dd("ModSecurity not enabled or an error occurred");
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->modsec_transaction == NULL || ctx->intervention_triggered) {
        return ngx_http_next_body_filter(r, in);
    }

    for (chain = in; chain != NULL; chain = chain->next) {
        buf = chain->buf;

        if (buf->pos != buf->last) {
            msc_append_response_body(ctx->modsec_transaction,
                buf->pos, buf->last - buf->pos);
            ret = ngx_http_modsecurity_process_intervention(ctx, r);
            if (ret > 0) {
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, ret);
            }
        }

        last_buf = buf->last_buf;
        if (!last_buf) {
            continue;
        }

        msc_process_response_body(ctx->modsec_transaction);
        ret = ngx_http_modsecurity_process_intervention(ctx, r);
        if (ret > 0) {
            return ret;
        }
        if (ret < 0) {
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }
    if (!last_buf) {
        dd("buffer was not fully loaded! ctx: %p", ctx);
    }

    return ngx_http_next_body_filter(r, in);
}
