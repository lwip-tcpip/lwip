/*
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *
 */

#include <stdio.h>

#include "lwip/apps/tftp_server.h"
#include "tftp_example.h"

#if LWIP_UDP

static void*
tftp_open(const char* fname, const char* mode, u8_t is_write)
{
  LWIP_UNUSED_ARG(mode);
  
  if (is_write) {
    return (void*)fopen(fname, "wb");
  } else {
    return (void*)fopen(fname, "rb");
  }
}

static void 
tftp_close(void* handle)
{
  fclose((FILE*)handle);
}

static int
tftp_read(void* handle, void* buf, int bytes)
{
  int ret = fread(buf, 1, bytes, (FILE*)handle);
  if (ret <= 0) {
    return -1;
  }
  return ret;
}

static int
tftp_write(void* handle, struct pbuf* p)
{
  while (p != NULL) {
    if (fwrite(p->payload, 1, p->len, (FILE*)handle) != (size_t)p->len) {
      return -1;
    }
    p = p->next;
  }
  
  return 0;
}

static const struct tftp_context tftp = {
  tftp_open,
  tftp_close,
  tftp_read,
  tftp_write
};

void
tftp_example_init(void)
{
  tftp_init(&tftp);
}

#endif /* LWIP_UDP */
