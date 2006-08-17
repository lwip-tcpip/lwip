/**
 * @file
 * [EXPERIMENTAL] Generic MIB tree structures.
 *
 * @todo namespace prefixes
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
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
 * Author: Christiaan Simons <christiaan.simons@axon.tv>
 */

#ifndef __LWIP_SNMP_STRUCTS_H__
#define __LWIP_SNMP_STRUCTS_H__

#include "lwip/opt.h"
#include "arch/cc.h"
#include "lwip/snmp.h"

#if SNMP_PRIVATE_MIB
#include "private_mib.h"
#endif

/* MIB object instance */
#define MIB_OBJECT_NONE 0 
#define MIB_OBJECT_SCALAR 1
#define MIB_OBJECT_TAB 2

/* MIB object access */
#define MIB_OBJECT_READ_ONLY 0
#define MIB_OBJECT_READ_WRITE 1
#define MIB_OBJECT_WRITE_ONLY 2
#define MIB_OBJECT_NOT_ACCESSIBLE 3

/** object definition returned by (get_object_def)() */
struct obj_def
{
  /* MIB_OBJECT_NONE (0), MIB_OBJECT_SCALAR (1), MIB_OBJECT_TAB (2) */
  u8_t instance;
  /* 0 read-only, 1 read-write, 2 write-only, 3 not-accessible */
  u8_t access;
  /* ASN type for this object */
  u8_t asn_type;
  /* value length (host length) */
  u16_t v_len;
  /* length of instance part of supplied object identifier */
  u8_t  id_inst_len;
  /* instance part of supplied object identifier */
  s32_t *id_inst_ptr; 
  /* optional value address hint */
  void *addr;
};

/** MIB const array node */
#define MIB_NODE_AR 0x01
/** MIB array node (mem_malloced from RAM) */
#define MIB_NODE_RA 0x02
/** MIB list root node (mem_malloced from RAM) */
#define MIB_NODE_LR 0x03
/** MIB node for external objects */
#define MIB_NODE_EX 0x04

/** node "base class" layout, the mandatory fields for a node  */
struct mib_node
{
  /** returns struct obj_def for the given object identifier */
  void (*get_object_def)(u8_t ident_len, s32_t *ident, struct obj_def *od);
  /** returns object value for the given object identifier,
     @note the caller must allocate at least len bytes for the value */
  void (*get_value)(struct obj_def *od, u16_t len, void *value);
  /** @todo set_value() */
  /** One out of MIB_NODE_AR, MIB_NODE_LR or MIB_NODE_EX */
  const u8_t node_type;
  /* array or max list length */
  const u16_t maxlength;
};

/** derived node, points to a fixed size const array
    of sub-identifiers plus a 'child' pointer */
struct mib_array_node
{
  /* inherited "base class" */
  const void (*get_object_def)(u8_t ident_len, s32_t *ident, struct obj_def *od);
  const void (*get_value)(struct obj_def *od, u16_t len, void *value);
  const u8_t node_type;
  const u16_t maxlength;

  /* aditional struct members */
  const s32_t *objid;
  struct mib_node* const *nptr;
};

/** derived node, points to a fixed size mem_malloced array
    of sub-identifiers plus a 'child' pointer */
struct mib_ram_array_node
{
  /* inherited "base class" */
  void (*get_object_def)(u8_t ident_len, s32_t *ident, struct obj_def *od);
  void (*get_value)(struct obj_def *od, u16_t len, void *value);
  u8_t node_type;
  u16_t maxlength;

  /* aditional struct members */
  s32_t *objid;
  struct mib_node **nptr;
};

struct mib_list_node
{
  struct mib_list_node *prev;  
  struct mib_list_node *next;
  s32_t objid;
  struct mib_node *nptr;
};

/** derived node, points to a doubly linked list
    of sub-identifiers plus a 'child' pointer */
struct mib_list_rootnode
{
  /* inherited "base class" */
  void (*get_object_def)(u8_t ident_len, s32_t *ident, struct obj_def *od);
  void (*get_value)(struct obj_def *od, u16_t len, void *value);
  u8_t node_type;
  u16_t maxlength;

  /* aditional struct members */
  struct mib_list_node *head;
  struct mib_list_node *tail;
  /* counts list nodes in list  */
  u16_t count;
};

/** derived node, has access functions for mib object in external memory or device
    using index ('idx'), with a range 0 .. (count - 1) to address these objects */
struct mib_external_node
{
  /* inherited "base class" */
  void (*get_object_def)(u8_t ident_len, s32_t *ident, struct obj_def *od);
  void (*get_value)(struct obj_def *od, u16_t len, void *value);
  u8_t node_type;
  u16_t maxlength;

  /* aditional struct members */
  void (*req_object_def)(u8_t ident_len, s32_t *ident);
  void (*getreq_value)(struct obj_def *od);

  /** compares object sub identifier with externally available id
      return zero when equal, nonzero when unequal */
  u16_t (*ident_cmp)(u16_t idx, s32_t sub_id);
  /** returns next pointer for given index (NULL for scalar 'leaf') */
  struct mib_extern_node* (*get_nptr)(u16_t idx);
  /* counts actual number of external objects  */
  u16_t count;
};

/** export MIB tree from mib2.c */
extern const struct mib_array_node internet;

/** export for use in private mib */
void noleafs_get_object_def(u8_t ident_len, s32_t *ident, struct obj_def *od);
void noleafs_get_value(struct obj_def *od, u16_t len, void *value);

struct mib_node* snmp_search_tree(struct mib_node *node, u8_t ident_len, s32_t *ident, struct obj_def *object_def);
struct mib_node* snmp_expand_tree(struct mib_node *node, u8_t ident_len, s32_t *ident, struct snmp_obj_id *oidret);
u8_t snmp_iso_prefix_tst(u8_t ident_len, s32_t *ident);
u8_t snmp_iso_prefix_expand(u8_t ident_len, s32_t *ident, struct snmp_obj_id *oidret);

#endif
