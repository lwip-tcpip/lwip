/**
 * pcapif_helper.c - This file is part of lwIP pcapif and provides helper functions
 * for managing the link state.
 */

#include "pcapif_helper.h"

#include <stdlib.h>
#include <stdio.h>

#include "lwip/arch.h"

#ifdef WIN32

#define WIN32_LEAN_AND_MEAN

#ifdef _MSC_VER
#pragma warning( push, 3 )
#endif
#include <windows.h>
#include <packet32.h>
#include <ntddndis.h>
#ifdef _MSC_VER
#pragma warning ( pop )
#endif

struct pcapifh_linkstate {
  LPADAPTER        lpAdapter;
  PPACKET_OID_DATA ppacket_oid_data;
};

struct pcapifh_linkstate* pcapifh_linkstate_init(char *adapter_name)
{
  struct pcapifh_linkstate* state = (struct pcapifh_linkstate*)malloc(sizeof(struct pcapifh_linkstate));
  if (state != NULL) {
    memset(state, 0, sizeof(struct pcapifh_linkstate));
    state->ppacket_oid_data = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA) + sizeof(NDIS_MEDIA_STATE));
    if (state->ppacket_oid_data == NULL) {
      free(state);
      state = NULL;
    } else {
      state->lpAdapter = PacketOpenAdapter((char*)adapter_name);
      if ((state->lpAdapter == NULL) || (state->lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        /* failed to open adapter */
        free(state);
        state = NULL;
      }
    }
  }
  return state;
}

enum pcapifh_link_event pcapifh_linkstate_get(struct pcapifh_linkstate* state)
{
  enum pcapifh_link_event ret = PCAPIF_LINKEVENT_UNKNOWN;
  if (state != NULL) {
    state->ppacket_oid_data->Oid    = OID_GEN_MEDIA_CONNECT_STATUS;
    state->ppacket_oid_data->Length = sizeof(NDIS_MEDIA_STATE);
    if (PacketRequest(state->lpAdapter, FALSE, state->ppacket_oid_data)) {
      NDIS_MEDIA_STATE fNdisMediaState;
      fNdisMediaState = (*((PNDIS_MEDIA_STATE)(state->ppacket_oid_data->Data)));
      ret = ((fNdisMediaState == NdisMediaStateConnected) ? PCAPIF_LINKEVENT_UP : PCAPIF_LINKEVENT_DOWN);
    }
  }
  return ret;
}

void pcapifh_linkstate_close(struct pcapifh_linkstate* state)
{
  if (state != NULL) {
    if (state->lpAdapter != NULL) {
      PacketCloseAdapter(state->lpAdapter);
    }
    if (state->ppacket_oid_data != NULL) {
      free(state->ppacket_oid_data);
    }
    free(state);
  }
}

/** Helper function for PCAPIF_RX_READONLY for windows: copy the date to a new
 * page which is set to READONLY after copying.
 * This is a helper to simulate hardware that receives to memory that cannot be
 * written by the CPU.
 */
void *
pcapifh_alloc_readonly_copy(void *data, size_t len)
{
  DWORD oldProtect;
  void *ret;
  if (len > 4096) {
    lwip_win32_platform_diag("pcapifh_alloc_readonly_copy: invalid len: %d\n", len);
    while(1);
  }
  ret = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
  if (ret == NULL) {
    lwip_win32_platform_diag("VirtualAlloc failed: %d\n", GetLastError());
    while(1);
  }
  memcpy(ret, data, len);
  if (!VirtualProtect(ret, len, PAGE_READONLY, &oldProtect)) {
    lwip_win32_platform_diag("VirtualProtect failed: %d\n", GetLastError());
    while(1);
  }
  printf("pcapifh_alloc_readonly_copy(%d): 0x%08x\n", len, ret);
  return ret;
}

void
pcapifh_free_readonly_mem(void *data)
{
  if (!VirtualFree(data, 0, MEM_RELEASE)) {
    lwip_win32_platform_diag("VirtualFree(0x%08x) failed: %d\n", data, GetLastError());
    while(1);
  }
}

#else /* WIN32 */

/* @todo: add linux/unix implementation? */

struct pcapifh_linkstate {
  u8_t empty;
};

struct pcapifh_linkstate* pcapifh_linkstate_init(char *adapter_name)
{
  LWIP_UNUSED_ARG(adapter_name);
  return NULL;
}

enum pcapifh_link_event pcapifh_linkstate_get(struct pcapifh_linkstate* state)
{
  LWIP_UNUSED_ARG(state);
  return PCAPIF_LINKEVENT_UP;
}
void pcapifh_linkstate_close(struct pcapifh_linkstate* state)
{
  LWIP_UNUSED_ARG(state);
}

#endif /* WIN32 */
