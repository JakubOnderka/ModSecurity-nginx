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


static ngx_int_t
ngx_http_modsecurity_set_hostname(ngx_http_modsecurity_ctx_t *ctx, ngx_http_request_t *r)
{
#if defined(MODSECURITY_CHECK_VERSION) && MODSECURITY_VERSION_NUM >= 30130100
    u_char hostname_buf[256];

    ngx_str_t hostname;
    hostname.len = 0;
    hostname.data = NULL;

    // first check if Nginx received a Host header and it's usable
    // (i.e. not empty)
    // if yes, we can use that
    if (r->headers_in.server.len > 0) {
        hostname = r->headers_in.server;
    } else {
        // otherwise we try to use the server config, namely the
        // server_name $SERVER_NAME
        // directive
        // for eg. in default config, server_name is "_"
        // possible all requests without a Host header will be
        // handled by this server block
        ngx_http_core_srv_conf_t  *cscf;
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        if (cscf->server_name.len > 0) {
            hostname = cscf->server_name;
        } else {
            // hostname is empty
            return NGX_OK;
        }
    }

    // Hostname is usually short and should be under 255 chars, so in that cases
    // we don't need to allocate
    char *hostname_char;
    if (hostname.len < sizeof(hostname_buf)) {
        ngx_memcpy(hostname_buf, hostname.data, hostname.len);
        hostname_buf[hostname.len] = '\0';
        hostname_char = (char *) hostname_buf;
    } else {
        hostname_char = ngx_str_to_char(hostname, r->pool);
        if (hostname_char == (char*)-1) {
            return NGX_ERROR;
        }
    }

    // set the hostname in the transaction
    // this function is only available in ModSecurity 3.0.13 and later
    msc_set_request_hostname(ctx->modsec_transaction, (const unsigned char *)hostname_char);
#endif
    return NGX_OK;
}


ngx_int_t
ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r)
{
    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_ctx_t   *ctx;
    ngx_http_modsecurity_conf_t  *mcf;
    ngx_int_t                     ret;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1) {
        dd("ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }

    dd("catching a new _rewrite_ phase handler");

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    dd("recovering ctx: %p", ctx);

    if (ctx != NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_modsecurity_create_ctx(r);

    dd("ctx was NULL, creating new context: %p", ctx);

    if (ctx == NULL) {
        dd("ctx still null; Nothing we can do, returning an error.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    int client_port = ngx_inet_get_port(r->connection->sockaddr);
    int server_port = ngx_inet_get_port(r->connection->local_sockaddr);

    // Convert client address to null terminated string
    u_char client_addr[NGX_SOCKADDR_STRLEN + 1];
    ngx_memcpy(client_addr, r->connection->addr_text.data, r->connection->addr_text.len);
    client_addr[r->connection->addr_text.len] = '\0';

    // Convert local address to server_addr with null termination
    ngx_str_t s;
    u_char server_addr[NGX_SOCKADDR_STRLEN + 1];
    s.len = NGX_SOCKADDR_STRLEN;
    s.data = server_addr;
    if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    server_addr[s.len] = '\0';

    if (ngx_http_modsecurity_set_hostname(ctx, r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_connection(ctx->modsec_transaction,
        (const char *) client_addr, client_port,
        (const char *) server_addr, server_port);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    /**
     *
     * FIXME: Check how we can finalize a request without crash nginx.
     *
     * I don't think nginx is expecting to finalize a request at that
     * point as it seems that it clean the ngx_http_request_t information
     * and try to use it later.
     *
     */
    dd("Processing intervention with the connection information filled in");
    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ret;
    }

    const char *http_version;
    switch (r->http_version) {
        case NGX_HTTP_VERSION_9:
            http_version = "0.9";
            break;
        case NGX_HTTP_VERSION_10:
            http_version = "1.0";
            break;
        case NGX_HTTP_VERSION_11:
            http_version = "1.1";
            break;
#ifdef NGX_HTTP_VERSION_20
        case NGX_HTTP_VERSION_20:
            http_version = "2.0";
            break;
#endif
#ifdef NGX_HTTP_VERSION_30
        case NGX_HTTP_VERSION_30:
            http_version = "3.0";
            break;
#endif
        default:
            http_version = ngx_str_to_char(r->http_protocol, r->pool);
            if (http_version == (char*)-1) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if ((http_version != NULL) && (strlen(http_version) > 5) && (!strncmp("HTTP/", http_version, 5))) {
                http_version += 5;
            } else {
                http_version = "1.0";
            }
            break;
    }

    // Do not allocate new string for common methods
    const char *n_method;
    switch (r->method) {
        case NGX_HTTP_GET:
            n_method = "GET";
            break;
        case NGX_HTTP_HEAD:
            n_method = "HEAD";
            break;
        case NGX_HTTP_POST:
            n_method = "POST";
            break;
        case NGX_HTTP_PUT:
            n_method = "PUT";
            break;
        case NGX_HTTP_OPTIONS:
            n_method = "OPTIONS";
            break;
        case NGX_HTTP_CONNECT:
            n_method = "CONNECT";
            break;
        default:
            n_method = ngx_str_to_char(r->method_name, r->pool);
            if (n_method == (char*)-1) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            break;
    }

    if (r->unparsed_uri.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "modsecurity: unparsed uri is empty");
        return NGX_HTTP_BAD_REQUEST;
    }
    const char *n_uri = ngx_str_to_char(r->unparsed_uri, r->pool);
    if (n_uri == (char*)-1) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_uri(ctx->modsec_transaction, n_uri, n_method, http_version);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    dd("Processing intervention with the transaction information filled in (uri, method and version)");
    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ret;
    }

    /**
     * Since incoming request headers are already in place, lets send it to ModSecurity
     */
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    for (i = 0 ; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

        dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);
        msc_add_n_request_header(ctx->modsec_transaction,
            (const unsigned char *) data[i].key.data,
            data[i].key.len,
            (const unsigned char *) data[i].value.data,
            data[i].value.len);
    }


    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_request_headers(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    dd("Processing intervention with the request headers information filled in");
    ret = ngx_http_modsecurity_process_intervention(ctx, r);
    if (r->error_page) {
        return NGX_DECLINED;
    }
    if (ret > 0) {
        ctx->intervention_triggered = 1;
        return ret;
    }

    return NGX_DECLINED;
}
