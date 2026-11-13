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

void
ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_modsecurity_get_module_ctx(r);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


ngx_int_t
ngx_http_modsecurity_pre_access_handler(ngx_http_request_t *r)
{
    int                           ret;
    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_ctx_t   *ctx;

    dd("catching a new _preaccess_ phase handler");

    ctx = ngx_http_modsecurity_get_module_ctx(r);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ModSecurity not enabled or an error occured");
        return NGX_DECLINED;
    }

    if (ctx->request_body_processed) {
        return NGX_DECLINED;
    }

    if (ctx->intervention_triggered) {
        return NGX_DECLINED;
    }

    if (ctx->waiting_more_body == 1)
    {
        dd("waiting for more data before proceed. / count: %d",
            r->main->count);

        return NGX_DONE;
    }

    if (ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        ctx->body_requested = 1;

        dd("asking for the request body, if any. Count: %d",
            r->main->count);
        rc = ngx_http_read_client_request_body(r,
            ngx_http_modsecurity_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
    (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }
        if (rc == NGX_AGAIN)
        {
            dd("nginx is asking us to wait for more data.");

            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    dd("request body is ready to be processed");

    r->write_event_handler = ngx_http_core_run_phases;

    if (r->request_body->temp_file != NULL) {
        ngx_temp_file_t *temp_file = r->request_body->temp_file;
        off_t offset = 0;
        u_char buffer[8192];

        /* Ordinary spill files may already be unlinked on Unix. */
        while (offset < temp_file->offset) {
            size_t size = (size_t) ngx_min(
                (off_t) sizeof(buffer), temp_file->offset - offset);
            ssize_t n = ngx_read_file(&temp_file->file, buffer, size,
                offset);

            if (n == NGX_ERROR || n == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "modsecurity: failed to read request body file "
                    "\"%V\" at offset %O", &temp_file->file.name, offset);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            msc_append_request_body(ctx->modsec_transaction, buffer,
                (size_t) n);
            offset += n;

            ret = ngx_http_modsecurity_process_intervention(ctx, r);
            if (ret > 0) {
                return ret;
            }
        }
    } else {
        ngx_chain_t *chain = r->request_body->bufs;

        dd("inspection request body in memory.");

        while (chain) {
            u_char *data = chain->buf->pos;

            msc_append_request_body(ctx->modsec_transaction, data,
                chain->buf->last - data);

            if (chain->buf->last_buf) {
                break;
            }
            chain = chain->next;

            ret = ngx_http_modsecurity_process_intervention(ctx, r);
            if (ret > 0) {
                return ret;
            }
        }
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_request_body(ctx->modsec_transaction);
    ctx->request_body_processed = 1;
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (r->error_page) {
        return NGX_DECLINED;
    }
    if (ret > 0) {
        return ret;
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
    return NGX_DECLINED;
}
