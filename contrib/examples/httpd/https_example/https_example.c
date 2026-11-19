/**
 * @file
 * HTTPD https example
 *
 * This file demonstrates how to initialize httpd for https.
 * To do this, it needs 2 files:
 * - server certificate
 * - server private key
 *
 * In addition to that, watch out for resource shortage. You'll need plenty of
 * heap (start with MEM_SIZE >= 200 KByte or monitor its err counters) and be
 * sure to at least set the following settings high enough (monitor
 * lwip_stats for an idea of what's needed):
 * - MEMP_NUM_TCP_PCB/MEMP_NUM_ALTCP_PCB
 * - MEMP_NUM_TCPIP_MSG_INPKT
 * - MEMP_NUM_TCP_SEG
 */
 
 /*
 * Copyright (c) 2017-2019 Simon Goldschmidt
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 *
 */

#include "lwip/opt.h"
#include "https_example.h"

#include "lwip/altcp_tls.h"
#include "lwip/apps/httpd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** define LWIP_HTTPD_EXAMPLE_HTTPS to 1 to enable this file system */
#ifndef LWIP_HTTPD_EXAMPLE_HTTPS
#define LWIP_HTTPD_EXAMPLE_HTTPS 0
#endif

#if LWIP_HTTPD_EXAMPLE_HTTPS && LWIP_ALTCP_TLS

#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_USE_ADD_CERT_API
#define LWIP_HTTPD_EXAMPLE_HTTPS_USE_ADD_CERT_API 0
#endif

#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_ALPN
#define LWIP_HTTPD_EXAMPLE_HTTPS_ALPN 0
#endif

#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_INIT_HITLS
#define LWIP_HTTPD_EXAMPLE_HTTPS_INIT_HITLS LWIP_ALTCP_TLS_HITLS
#endif

#if LWIP_HTTPD_EXAMPLE_HTTPS_ALPN
#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_ALPN_PROTO
#define LWIP_HTTPD_EXAMPLE_HTTPS_ALPN_PROTO "http/1.1"
#endif
static const char *https_ex_alpn_protos[] = {
  LWIP_HTTPD_EXAMPLE_HTTPS_ALPN_PROTO,
  NULL
};
#endif

#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE
#error "define LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE to the created server private key"
#endif

/* If the key file is password-protected, define LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS */
#ifdef LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS
#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS_LEN
#define LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS_LEN  strlen(LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS)
#endif
#else
#define LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS      NULL
#define LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS_LEN  0
#endif

#ifndef LWIP_HTTPD_EXAMPLE_HTTPS_CERT_FILE
#error "define LWIP_HTTPD_EXAMPLE_HTTPS_CERT_FILE to the created server certificate"
#endif

static u8_t *read_file(const char *filename, size_t *file_size)
{
  u8_t *buf;
  long fsize;
  FILE *f = fopen(filename, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  buf = (u8_t *)malloc(fsize + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  fread(buf, 1, fsize, f);
  fclose(f);

  buf[fsize] = 0;
  if (file_size) {
    /* Note: the '+ 1' is required by TLS backends that parse PEM as C strings. */
    *file_size = (size_t)(fsize + 1);
  }
  return buf;
}

static struct altcp_tls_config *
https_ex_create_config(const u8_t *privkey, size_t privkey_size,
                       const u8_t *cert, size_t cert_size)
{
  struct altcp_tls_config *conf;

#if LWIP_HTTPD_EXAMPLE_HTTPS_USE_ADD_CERT_API
  err_t err;

  conf = altcp_tls_create_config_server(1);
  if (conf == NULL) {
    return NULL;
  }

  err = altcp_tls_config_server_add_privkey_cert(conf, privkey, privkey_size,
    LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS, LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS_LEN, cert, cert_size);
  if (err != ERR_OK) {
    altcp_tls_free_config(conf);
    return NULL;
  }
#else
  conf = altcp_tls_create_config_server_privkey_cert(privkey, privkey_size,
    LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS, LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE_PASS_LEN, cert, cert_size);
  if (conf == NULL) {
    return NULL;
  }
#endif

#if LWIP_HTTPD_EXAMPLE_HTTPS_ALPN
  if (altcp_tls_configure_alpn_protocols(conf, https_ex_alpn_protos) != 0) {
    altcp_tls_free_config(conf);
    return NULL;
  }
#endif

  return conf;
}

/** This function loads a server certificate and private key as x509 from disk.
 * For information how to create such files, see mbedTLS tutorial ("How to
 * generate a self-signed certificate") or OpenSSL documentation ("How to
 * generate a self-signed certificate and private key using OpenSSL"), e.g.
 * 'openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt'
 * Copy the resulting files and define the path to them
 */
void
https_ex_init(void)
{
  struct altcp_tls_config *conf;
  u8_t *privkey, *cert;
  size_t privkey_size, cert_size;

#if LWIP_HTTPD_EXAMPLE_HTTPS_INIT_HITLS
  LWIP_ASSERT("Failed to initialize openHiTLS", altcp_tls_hitls_init() == ERR_OK);
#endif

  privkey = read_file(LWIP_HTTPD_EXAMPLE_HTTPS_KEY_FILE, &privkey_size);
  LWIP_ASSERT("Failed to open https server private key", privkey != NULL);
  cert = read_file(LWIP_HTTPD_EXAMPLE_HTTPS_CERT_FILE, &cert_size);
  LWIP_ASSERT("Failed to open https server certificate", cert != NULL);

  conf = https_ex_create_config(privkey, privkey_size, cert, cert_size);
  LWIP_ASSERT("Failed to create https server config", conf != NULL);

  httpd_inits(conf);

  /* secure erase should be done in production environment */
  free(privkey);
  free(cert);
}

#endif /* LWIP_HTTPD_EXAMPLE_HTTPS */
