/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-memory BIER forwarding domain.
 */

#include "bier/bier.h"

#include <stdlib.h>
#include <string.h>

bier_domain_t *
bier_domain_new (void)
{
  return calloc (1, sizeof (bier_domain_t));
}

static void
free_nexthops (bier_nexthop_t *nh)
{
  while (nh)
    {
      bier_nexthop_t *next = nh->next;

      free (nh);
      nh = next;
    }
}

static void
free_table (bier_table_t *t)
{
  uint32_t i;

  if (!t)
    return;

  if (t->bp_map)
    {
      for (i = 0; i < t->bits; i++)
        {
          bier_entry_t *e = t->bp_map[i];

          if (e)
            {
              free_nexthops (e->nhs);
              free (e);
            }
        }
      free (t->bp_map);
    }
  free (t);
}

void
bier_domain_free (bier_domain_t *d)
{
  bier_table_t *t;
  bier_disp_table_t *dt;
  bier_imp_t *imp;

  if (!d)
    return;

  t = d->tables;
  while (t)
    {
      bier_table_t *next = t->next;

      free_table (t);
      t = next;
    }

  dt = d->disp_tables;
  while (dt)
    {
      bier_disp_table_t *next = dt->next;
      bier_disp_entry_t *e = dt->entries;

      while (e)
        {
          bier_disp_entry_t *enext = e->next;

          free (e);
          e = enext;
        }
      free (dt);
      dt = next;
    }

  imp = d->imps;
  while (imp)
    {
      bier_imp_t *next = imp->next;

      free (imp);
      imp = next;
    }

  free (d);
}

bier_table_t *
bier_domain_add_table (bier_domain_t *d, uint32_t id, uint8_t set, uint8_t sd,
                       bier_bsl_t bsl)
{
  bier_table_t *t;
  size_t nbytes = bier_bsl_bytes (bsl);

  if (nbytes == 0)
    return NULL;

  t = calloc (1, sizeof (*t));
  if (!t)
    return NULL;

  t->id = id;
  t->set = set;
  t->sd = sd;
  t->bsl = bsl;
  t->nbytes = nbytes;
  t->bits = (uint32_t) (nbytes * 8);
  t->bp_map = calloc (t->bits, sizeof (*t->bp_map));
  if (!t->bp_map)
    {
      free (t);
      return NULL;
    }

  t->next = d->tables;
  d->tables = t;
  return t;
}

bier_table_t *
bier_domain_find_table_by_id (const bier_domain_t *d, uint32_t id)
{
  bier_table_t *t;

  for (t = d->tables; t; t = t->next)
    if (t->id == id)
      return t;
  return NULL;
}

bier_table_t *
bier_domain_find_table_by_bift (const bier_domain_t *d, uint32_t bift_id)
{
  bier_table_t *t;

  for (t = d->tables; t; t = t->next)
    if (bier_bift_id_encode (t->set, t->sd, t->bsl) == bift_id)
      return t;
  return NULL;
}

bier_entry_t *
bier_table_add_entry (bier_table_t *t, uint16_t bp)
{
  bier_entry_t *e;

  if (!t || bp == 0 || bp > t->bits)
    return NULL;

  e = t->bp_map[bp - 1];
  if (e)
    return e;

  e = calloc (1, sizeof (*e));
  if (!e)
    return NULL;

  e->bp = bp;
  t->bp_map[bp - 1] = e;
  t->n_entries++;
  return e;
}

bier_nexthop_t *
bier_entry_add_nexthop (bier_entry_t *e, uint32_t addr, uint16_t port)
{
  bier_nexthop_t *nh;
  bier_nexthop_t **tail;

  if (!e)
    return NULL;

  nh = calloc (1, sizeof (*nh));
  if (!nh)
    return NULL;

  nh->addr = addr;
  nh->port = port;
  nh->disp_id = -1;

  tail = &e->nhs;
  while (*tail)
    tail = &(*tail)->next;
  *tail = nh;
  e->n_nh++;
  return nh;
}

bier_nexthop_t *
bier_entry_add_disp_nexthop (bier_entry_t *e, int32_t disp_id)
{
  bier_nexthop_t *nh;
  bier_nexthop_t **tail;

  if (!e || disp_id < 0)
    return NULL;

  nh = calloc (1, sizeof (*nh));
  if (!nh)
    return NULL;

  nh->disp_id = disp_id;

  tail = &e->nhs;
  while (*tail)
    tail = &(*tail)->next;
  *tail = nh;
  e->n_nh++;
  return nh;
}

bier_disp_table_t *
bier_domain_add_disp_table (bier_domain_t *d, uint32_t id)
{
  bier_disp_table_t *dt = calloc (1, sizeof (*dt));

  if (!dt)
    return NULL;

  dt->id = id;
  dt->next = d->disp_tables;
  d->disp_tables = dt;
  return dt;
}

bier_disp_table_t *
bier_domain_find_disp_table (const bier_domain_t *d, uint32_t id)
{
  bier_disp_table_t *dt;

  for (dt = d->disp_tables; dt; dt = dt->next)
    if (dt->id == id)
      return dt;
  return NULL;
}

void
bier_disp_table_add_entry (bier_disp_table_t *dt, uint16_t sender, uint8_t proto,
                           uint32_t addr, uint16_t port)
{
  bier_disp_entry_t *e;
  bier_disp_entry_t **tail;

  if (!dt)
    return;

  e = calloc (1, sizeof (*e));
  if (!e)
    return;

  e->sender = sender;
  e->proto = proto;
  e->addr = addr;
  e->port = port;

  tail = &dt->entries;
  while (*tail)
    tail = &(*tail)->next;
  *tail = e;
}

bier_imp_t *
bier_domain_add_imposition (bier_domain_t *d, uint32_t id, uint32_t table_id,
                            uint16_t sender)
{
  bier_imp_t *imp = calloc (1, sizeof (*imp));

  if (!imp)
    return NULL;

  imp->id = id;
  imp->table_id = table_id;
  imp->sender = sender;
  imp->next = d->imps;
  d->imps = imp;
  return imp;
}

bier_imp_t *
bier_domain_find_imposition (const bier_domain_t *d, uint32_t id)
{
  bier_imp_t *imp;

  for (imp = d->imps; imp; imp = imp->next)
    if (imp->id == id)
      return imp;
  return NULL;
}
