/**
 * @file
 * [EXPERIMENTAL] Generic MIB tree access/construction functions.
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

#include "lwip/opt.h"

#if LWIP_SNMP
#include "lwip/snmp_structs.h"

/** .iso.org.dod.internet address prefix, @see snmp_iso_*() */
const s32_t prefix[4] = {1, 3, 6, 1};

#define NODE_STACK_SIZE (LWIP_SNMP_OBJ_ID_LEN)
/** node stack entry (old news?) */
struct nse
{
  /** right child */
  struct mib_node* r_ptr;
  /** right child identifier */
  s32_t r_id;
};
static u8_t node_stack_cnt = 0;
static struct nse node_stack[NODE_STACK_SIZE];

static void
push_node(struct nse* node)
{
  LWIP_ASSERT("node_stack_cnt < NODE_STACK_SIZE",node_stack_cnt < NODE_STACK_SIZE);
  if (node_stack_cnt < NODE_STACK_SIZE)
  {
    node_stack[node_stack_cnt] = *node;
    node_stack_cnt++;
  }
}

static void
pop_node(struct nse* node)
{
  if (node_stack_cnt > 0)
  {
    node_stack_cnt--;
    *node = node_stack[node_stack_cnt];
  }
}

/**
 * Searches tree for the supplied (scalar?) object identifier.
 *
 * @param node points to the root of the tree ('.internet')
 * @param ident_len the length of the supplied object identifier
 * @param ident points to the array of sub identifiers
 * @param object_def points to the object definition to return
 * @return pointer to the requested parent (!) node if success, NULL otherwise
 */
struct mib_node *
snmp_search_tree(struct mib_node *node, u8_t ident_len, s32_t *ident, struct obj_def *object_def)
{
  u8_t node_type;

  LWIP_DEBUGF(SNMP_MIB_DEBUG,("node==%p *ident==%"S32_F,(void*)node,*ident));
  while (node != NULL)
  {
    node_type = node->node_type;
    if ((node_type == MIB_NODE_AR) || (node_type == MIB_NODE_RA))
    {
      struct mib_array_node *an;
      u16_t i;

      if (ident_len > 0)
      { 
        /* array node (internal ROM or RAM, fixed length) */
        an = (struct mib_array_node *)node;
        i = 0;
        while ((i < an->maxlength) && (an->objid[i] != *ident))
        {
          i++;
        }
        if (i < an->maxlength)
        {
          /* found it, if available proceed to child, otherwise inspect leaf */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("an->objid[%"U16_F"]==%"S32_F" *ident==%"S32_F,i,an->objid[i],*ident));
          if (an->nptr[i] == NULL)
          {
            /* a scalar leaf OR table,
               inspect remaining instance number / table index */
            /* retrieve object definition with get_object_def() 
               is it scalar, or a valid table item, or non-existent? */
            an->get_object_def(ident_len, ident, object_def);
            if (object_def->instance != MIB_OBJECT_NONE)
            {
              /** @todo return something more usefull ?? */
              return (struct mib_node*)an;
            }
            else
            {
              /* search failed, object id points to unknown object (nosuchname) */
              LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, object not in this MIB"));
              return NULL;
            }
          }
          else
          {
            /* follow next child pointer */
            ident++;
            ident_len--;
            node = an->nptr[i];
          }
        }
        else
        {
          /* search failed, identifier mismatch (nosuchname) */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
          return NULL;
        }
      }
      else
      {
        /* search failed, short object identifier (nosuchname) */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
        return NULL;
      }
    }
    else if(node_type == MIB_NODE_LR)
    {
      struct mib_list_rootnode *lrn;
      struct mib_list_node *ln;

      if (ident_len > 0)
      {
        /* list root node (internal 'RAM', variable length) */
        lrn = (struct mib_list_rootnode *)node;
        ln = lrn->head;
        /* iterate over list, head to tail */
        while ((ln != NULL) && (ln->objid != *ident))
        {
          ln = ln->next;
        }
        if (ln != NULL)
        {
          /* found it, proceed to child */;
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("ln->objid==%"S32_F" *ident==%"S32_F,ln->objid,*ident));
          if (ln->nptr == NULL)
          {
            lrn->get_object_def(ident_len, ident, object_def);
            if (object_def->instance != MIB_OBJECT_NONE)
            {
              /** @todo return something more usefull ?? */
              return (struct mib_node*)lrn;
            }
            else
            {
              /* search failed, object id points to unknown object (nosuchname) */
              LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, object not in this MIB"));
              return NULL;
            }
          }
          else
          {
            /* follow next child pointer */
            ident_len--;
            ident++;
            node = ln->nptr;
          }
        }
        else
        {
          /* search failed */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
          return NULL;
        }
      }
      else
      {
        /* search failed, short object identifier (nosuchname) */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
        return NULL;
      }
    }
    else if(node_type == MIB_NODE_EX)
    {
      struct mib_external_node *en;
      u16_t i;

      if (ident_len > 0)
      { 
        /* external node (addressing and access via functions) */
        en = (struct mib_external_node *)node;
        i = 0;
        while ((i < en->count) && en->ident_cmp(i,*ident))
        {
          i++;
        }
        if (i < en->count)
        {
          if (en->get_nptr(i) == NULL)
          {
/** @todo, this object is elsewhere, we can only start the request,
     but can't return something usefull yet.*/
            en->req_object_def(ident_len, ident);
            return (struct mib_node*)en;
          }
          else
          {
            /* found it, proceed to child */
            ident_len--;
            ident++;
            node = (struct mib_node*)en->get_nptr(i);
          }
        }
        else
        {
          /* search failed */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
          return NULL;
        }
      }
      else
      {
        /* search failed, short object identifier (nosuchname) */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
        return NULL;
      }
    }
    else
    {
      /* unknown node_type */
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed node_type %"U16_F" unkown",(u16_t)node_type));
      return NULL;
    }
  }
  /* done, found nothing */
  LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed node==%p",(void*)node));
  return NULL;
}

/**
 * Tree expansion.
 *
 * @todo function ptrs for tabular items 
 *       if not empty add first index, nextThing.0 otherwise
 */
struct mib_node *
snmp_expand_tree(struct mib_node *node, u8_t ident_len, s32_t *ident, struct snmp_obj_id *oidret)
{
  u8_t node_type;

  /* reset stack */
  node_stack_cnt = 0;

  while (node != NULL)
  {
    node_type = node->node_type;
    if ((node_type == MIB_NODE_AR) || (node_type == MIB_NODE_RA))
    {
      struct mib_array_node *an;
      u16_t i;
      u8_t climb_tree;

      /* array node (internal ROM or RAM, fixed length) */
      an = (struct mib_array_node *)node;
      if (ident_len > 0)
      {
        i = 0;
        while ((i < an->maxlength) && (an->objid[i] < *ident))
        {
          i++;
        }
        if (i < an->maxlength)
        {
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("an->objid[%"U16_F"]==%"S32_F" *ident==%"S32_F,i,an->objid[i],*ident));

          climb_tree = 0;

          /* add identifier to oidret */
          oidret->id[oidret->len] = an->objid[i];
          (oidret->len)++;
        
          if (an->nptr[i] == NULL)
          {
            /* leaf node,            /*
               if scalar: if ident_len == 1 add '.0', nextThing.0 otherwise */
            if (ident_len == 1)
            {
              oidret->id[oidret->len] = 0;
              (oidret->len)++;
              return (struct mib_node*)an;
            }
            else if ((i + 1) < an->maxlength)
            {
              (oidret->len)--;
              oidret->id[oidret->len] = an->objid[i + 1];
              (oidret->len)++;
              oidret->id[oidret->len] = 0;
              (oidret->len)++;
              return (struct mib_node*)an;
            }
            else
            {
              (oidret->len)--;
              climb_tree = 1;
            }
          }
          else
          {
            struct nse cur_node;

            /* non-leaf, store right child ptr and id */
            if ((i + 1) < an->maxlength)
            {
              cur_node.r_ptr = an->nptr[i + 1];
              cur_node.r_id = an->objid[i + 1];
            }
            else
            {
              cur_node.r_ptr = NULL;
            }
            LWIP_DEBUGF(SNMP_MIB_DEBUG,("expand, push_node() node=%p id=%"S32_F,cur_node.r_ptr,cur_node.r_id));
            push_node(&cur_node);
            /* follow next child pointer */
            ident_len--;
            ident++;
            node = an->nptr[i];
          }
        }
        else
        {
          /* i == an->maxlength */
          climb_tree = 1;
        }

        if (climb_tree)
        {
          struct nse child;

          /* find right child ptr */
          child.r_ptr = NULL;
          while ((node_stack_cnt > 0) && (child.r_ptr == NULL))
          {
            pop_node(&child);
            LWIP_DEBUGF(SNMP_MIB_DEBUG,("expand, pop_node() node=%p id=%"S32_F, child.r_ptr, child.r_id));
            /* trim returned oid */
            (oidret->len)--;
          }
          if (child.r_ptr != NULL)
          {
            /* incoming ident is useless beyond this point */
            ident_len = 0;
            oidret->id[oidret->len] = child.r_id;
            oidret->len++;
            node = child.r_ptr;
          }
          else
          {
            /* tree ends here ... */
            LWIP_DEBUGF(SNMP_MIB_DEBUG,("expand failed, tree ends here"));
            return NULL;
          }
        }
      }
      else
      {
        /* ident_len == 0, complete object identifier */
        /* add leftmost '.thing' */
        oidret->id[oidret->len] = an->objid[0];
        (oidret->len)++;
        if (an->nptr[0] == NULL)
        {
          /* leaf node
             if scalar: add '.0' */
          oidret->id[oidret->len] = 0;
          (oidret->len)++;
          return (struct mib_node*)an;
        }
        else
        {
          /* no leaf, continue */
          node = an->nptr[0];
        }
      }
    }
    else
    {
      /* unknown/unhandled node_type */
      LWIP_DEBUGF(SNMP_MIB_DEBUG,("expand failed node_type %"U16_F" unkown",(u16_t)node_type));
      return NULL;
    }
  }
  /* done, found nothing */
  LWIP_DEBUGF(SNMP_MIB_DEBUG,("expand failed node==%p",(void*)node));
  return NULL;
}

/**
 * Test object identifier for the iso.org.dod.internet prefix.
 *
 * @param ident_len the length of the supplied object identifier
 * @param ident points to the array of sub identifiers
 * @return 1 if it matches, 0 otherwise
 */
u8_t
snmp_iso_prefix_tst(u8_t ident_len, s32_t *ident)
{
  if ((ident_len > 3) &&
      (ident[0] == 1) && (ident[1] == 3) &&
      (ident[2] == 6) && (ident[3] == 1))
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

/**
 * Expands object identifier to the iso.org.dod.internet
 * prefix for use in getnext operation.
 *
 * @param ident_len the length of the supplied object identifier
 * @param ident points to the array of sub identifiers
 * @param oidret points to returned expanded object identifier
 * @return 1 if it matches, 0 otherwise
 *
 * @note ident_len 0 is allowed, expanding to the first known object id!!
 */
u8_t
snmp_iso_prefix_expand(u8_t ident_len, s32_t *ident, struct snmp_obj_id *oidret)
{
  const s32_t *prefix_ptr;
  s32_t *ret_ptr;
  u8_t i;

  i = 0;
  prefix_ptr = &prefix[0];
  ret_ptr = &oidret->id[0];
  ident_len = ((ident_len < 4)?ident_len:4);
  while ((i < ident_len) && ((*ident) <= (*prefix_ptr)))
  {
    *ret_ptr++ = *prefix_ptr++;
    ident++;
    i++;
  }
  if (i == ident_len)
  {
    /* match, complete missing bits */
    while (i < 4)
    {
      *ret_ptr++ = *prefix_ptr++;
      i++;
    }
    oidret->len = i;
    return 1;
  }
  else
  {
    /* i != ident_len */
    return 0;
  }
}

#endif /* LWIP_SNMP */

