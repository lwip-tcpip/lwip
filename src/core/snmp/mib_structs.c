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
#include "lwip/snmp_structs.h"

#if LWIP_SNMP

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

      /* array node (internal ROM or RAM, fixed length) */
      an = (struct mib_array_node *)node;
      i = 0;
      while ((i < an->maxlength) && (an->objid[i] != *ident))
      {
        i++;
      }
      if (i < an->maxlength)
      {
        if (ident_len > 0)
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
          /* search failed, short object identifier (nosuchname) */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
          return NULL;
        }
      }
      else
      {
        /* search failed, identifier mismatch (nosuchname) */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
        return NULL;
      }
    }
    else if(node_type == MIB_NODE_LR)
    {
      struct mib_list_rootnode *lrn;
      struct mib_list_node *ln;

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
        if (ident_len > 0)
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
          /* search failed, short object identifier (nosuchname) */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
          return NULL;
        }
      }
      else
      {
        /* search failed */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
        return NULL;
      }
    }
    else if(node_type == MIB_NODE_EX)
    {
      struct mib_external_node *en;
      u16_t i;

      /* external node (addressing and access via functions) */
      en = (struct mib_external_node *)node;
      i = 0;
      while ((i < en->count) && en->ident_cmp(i,*ident))
      {
        i++;
      }
      if (i < en->count)
      {
        if (ident_len > 0)
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
          /* search failed, short object identifier (nosuchname) */
          LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed, short object identifier"));
          return NULL;
        }
      }
      else
      {
        /* search failed */
        LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed *ident==%"S32_F,*ident));
        return NULL;
      }
    }
  }
  /* done, found nothing */
  LWIP_DEBUGF(SNMP_MIB_DEBUG,("search failed node==%p",(void*)node));
  return NULL;
}

#endif /* LWIP_SNMP */
