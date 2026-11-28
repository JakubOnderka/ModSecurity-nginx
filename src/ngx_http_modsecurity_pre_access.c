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

static ngx_http_request_body_filter_pt
    ngx_http_modsecurity_next_request_body_filter;

static ngx_int_t
ngx_http_modsecurity_append_body(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, u_char *data, size_t len)
{
    int ret;

    if (len == 0 || ctx->request_body_limit_reached) {
        return NGX_OK;
    }

    ret = msc_append_request_body(ctx->modsec_transaction, data, len);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "modsecurity: appended request body buffer %uz for \"%V\"",
                  len, &r->uri);

    /* ProcessPartial returns zero once its inspection limit is reached. */
    if (ret == 0) {
        ctx->request_body_limit_reached = 1;
    }

    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ret;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_chain_t *cl;
    ngx_int_t rc;

    /* Subrequests may share the main request's pool and buffered body. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL || !ctx->body_requested || ctx->request_body_processed
        || ctx->intervention_triggered)
    {
        return ngx_http_modsecurity_next_request_body_filter(r, in);
    }

    ctx->request_body_filter_seen = 1;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            rc = ngx_http_modsecurity_append_body(r, ctx, cl->buf->pos,
                cl->buf->last - cl->buf->pos);
            if (rc != NGX_OK) {
                return rc;
            }
        } else if (ngx_buf_size(cl->buf) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "modsecurity: non-memory buffer in request body filter");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* The next filter owns these buffers and may save them to disk. */
    return ngx_http_modsecurity_next_request_body_filter(r, in);
}

ngx_int_t
ngx_http_modsecurity_request_body_filter_init(void)
{
    ngx_http_modsecurity_next_request_body_filter =
        ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter =
        ngx_http_modsecurity_request_body_filter;
    return NGX_OK;
}

void
ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_modsecurity_get_module_ctx(r);

#if defined(nginx_version) && nginx_version >= 8011
    if (ctx == NULL || !ctx->waiting_more_body) {
        r->main->count--;
    }
#endif

    if (ctx != NULL && ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


ngx_int_t
ngx_http_modsecurity_pre_access_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t   *ctx;

    dd("catching a new _preaccess_ phase handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ModSecurity not enabled or an error occured");
        return NGX_DECLINED;
    }

    if (ctx->request_body_processed) {
        // should we use r->internal or r->filter_finalize?
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

        if (r->reading_body || r->request_body_no_buffering) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "modsecurity: cannot inspect a request body "
                          "already being read without buffering");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

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
#if defined(nginx_version) && nginx_version >= 8011
            /* The callback is not called when an asynchronous read fails. */
            r->main->count--;
#endif
            return NGX_DONE;
        }
    }

    if (ctx->waiting_more_body == 0)
    {
        int ret = 0;
        ngx_int_t rc;

        dd("request body is ready to be processed");

        r->write_event_handler = ngx_http_core_run_phases;

        if (r->request_body == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "modsecurity: missing request body after body read");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_chain_t *chain = r->request_body->bufs;

        /* Another module may have read the body before our context existed. */
        if (!ctx->request_body_filter_seen
            && r->request_body->temp_file != NULL)
        {
            ngx_temp_file_t *temp_file = r->request_body->temp_file;
            off_t offset = 0;
            u_char buffer[64 * 1024];

            /* Ordinary spill files may already be unlinked on Unix. */
            while (offset < temp_file->offset
                   && !ctx->request_body_limit_reached)
            {
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

                rc = ngx_http_modsecurity_append_body(r, ctx, buffer,
                    (size_t) n);
                offset += n;

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            ctx->request_body_filter_seen = 1;
        }

        while (chain && !ctx->request_body_filter_seen)
        {
            if (ngx_buf_in_memory(chain->buf)) {
                rc = ngx_http_modsecurity_append_body(r, ctx, chain->buf->pos,
                    chain->buf->last - chain->buf->pos);
                if (rc != NGX_OK) {
                    return rc;
                }
            } else if (ngx_buf_size(chain->buf) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "modsecurity: unsupported buffered request body");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            chain = chain->next;
        }

        /**
         * At this point, all the request body was sent to ModSecurity
         * and we want to make sure that all the request body inspection
         * happened; consequently we have to check if ModSecurity have
         * returned any kind of intervention.
         */

/* XXX: once more -- is body can be modified ?  content-length need to be adjusted ? */

        msc_process_request_body(ctx->modsec_transaction);
        ctx->request_body_processed = 1;

        ret = ngx_http_modsecurity_process_intervention(ctx, r);
        if (r->error_page) {
            return NGX_DECLINED;
        }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
    return NGX_DECLINED;
}

