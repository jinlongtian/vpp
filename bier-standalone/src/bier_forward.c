/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * BIER forwarding, imposition and disposition.
 *
 * The replication algorithm mirrors VPP's bier-lookup/bier-output pair:
 *   - walk the bit-string from the lowest bit-position;
 *   - group bit-positions that resolve to the same next-hop;
 *   - emit one copy per next-hop with the group's bit-string.
 */

#include "bier/bier.h"

#include <stdlib.h>
#include <string.h>

#define BIER_BITSTRING_OFFSET (BIER_BIFT_WIRE_LEN + BIER_HEADER_FIXED_LEN)

typedef struct
{
  bier_nexthop_t *nh;
  uint8_t mask[BIER_MAX_BSL_BYTES];
} bier_group_t;

static inline uint32_t
read_be32 (const uint8_t *p)
{
  return (((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
          ((uint32_t) p[2] << 8) | (uint32_t) p[3]);
}

static inline void
write_be32 (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) v;
}

static bier_nexthop_t *
choose_nexthop (const bier_entry_t *e, uint32_t entropy)
{
  bier_nexthop_t *nh;
  uint32_t idx;
  uint32_t i;

  if (!e || e->n_nh == 0)
    return NULL;

  idx = entropy % e->n_nh;
  nh = e->nhs;
  for (i = 0; i < idx && nh; i++)
    nh = nh->next;
  return nh;
}

static bier_group_t *
group_find (bier_group_t *groups, uint32_t n_groups, bier_nexthop_t *nh)
{
  uint32_t i;

  for (i = 0; i < n_groups; i++)
    if (groups[i].nh == nh)
      return &groups[i];
  return NULL;
}

static bier_disp_entry_t *
disp_lookup (bier_domain_t *d, int32_t disp_id, uint16_t sender, uint8_t proto)
{
  bier_disp_table_t *dt;
  uint16_t senders[2];
  int s;

  dt = bier_domain_find_disp_table (d, (uint32_t) disp_id);
  if (!dt)
    return NULL;

  senders[0] = sender;
  senders[1] = 0;

  for (s = 0; s < 2; s++)
    {
      bier_disp_entry_t *e;

      for (e = dt->entries; e; e = e->next)
        {
          if (e->sender != senders[s])
            continue;
          if (e->proto == proto || e->proto == BIER_PROTO_ANY)
            return e;
        }
    }
  return NULL;
}

static uint32_t
fnv1a_entropy (const uint8_t *p, size_t len)
{
  uint32_t h = 2166136261u;
  size_t i;
  size_t n = len < 64 ? len : 64;

  for (i = 0; i < n; i++)
    {
      h ^= p[i];
      h *= 16777619u;
    }
  return (h & 0xfffffu);
}

static int
forward_packet (bier_domain_t *d, const uint8_t *pkt, size_t len,
                bier_emit_fn emit, void *ctx, int count_rx)
{
  bier_header_t h;
  bier_table_t *t;
  bier_group_t *groups = NULL;
  uint8_t work[BIER_MAX_BSL_BYTES];
  uint8_t *out = NULL;
  uint32_t wire, count, n_groups = 0, bp;
  uint8_t set, sd, ttl, out_ttl;
  bier_bsl_t bsl;
  size_t nbytes;
  int rc = -1;

  if (!d || !pkt || !emit || len < BIER_BIFT_WIRE_LEN + BIER_HEADER_FIXED_LEN)
    return -1;

  if (count_rx)
    d->stats.rx++;

  wire = read_be32 (pkt);
  if (!bier_bift_wire_decode (wire, &set, &sd, &bsl, &ttl))
    {
      d->stats.drop_bad_header++;
      return -1;
    }

  t = bier_domain_find_table_by_bift (d, bier_bift_id_encode (set, sd, bsl));
  if (!t)
    {
      d->stats.drop_no_table++;
      return -1;
    }

  if (ttl == 0)
    {
      d->stats.drop_ttl++;
      return -1;
    }

  if (bier_header_parse (pkt + BIER_BIFT_WIRE_LEN,
                         len - BIER_BIFT_WIRE_LEN, &h) < 0)
    {
      d->stats.drop_bad_header++;
      return -1;
    }

  if (h.version != BIER_HEADER_VERSION || h.bsl != bsl)
    {
      d->stats.drop_bad_header++;
      return -1;
    }

  nbytes = h.bitstring_len;
  if (len < BIER_BITSTRING_OFFSET + nbytes)
    {
      d->stats.drop_bad_header++;
      return -1;
    }

  count = bier_bs_count (h.bitstring, nbytes);
  if (count == 0)
    {
      d->stats.drop_no_entry++;
      return -1;
    }

  groups = calloc (count, sizeof (*groups));
  out = malloc (len);
  if (!groups || !out)
    goto done;

  memcpy (work, h.bitstring, nbytes);

  while ((bp = bier_bs_first (work, nbytes)) != 0)
    {
      bier_entry_t *e = bp <= t->bits ? t->bp_map[bp - 1] : NULL;
      bier_nexthop_t *nh;
      bier_group_t *g;

      if (!e)
        {
          bier_bs_clear (work, nbytes, bp);
          d->stats.drop_no_entry++;
          continue;
        }

      nh = choose_nexthop (e, h.entropy);
      if (!nh)
        {
          bier_bs_clear (work, nbytes, bp);
          d->stats.drop_no_entry++;
          continue;
        }

      g = group_find (groups, n_groups, nh);
      if (!g)
        {
          g = &groups[n_groups++];
          g->nh = nh;
          memset (g->mask, 0, sizeof (g->mask));
        }

      bier_bs_set (g->mask, nbytes, bp);
      bier_bs_clear (work, nbytes, bp);
      e->pkts++;
    }

  if (n_groups == 0)
    {
      rc = 0;
      goto done;
    }

  out_ttl = (uint8_t) (ttl - 1);

  for (uint32_t i = 0; i < n_groups; i++)
    {
      bier_group_t *g = &groups[i];

      if (g->nh->disp_id >= 0)
        {
          bier_disp_entry_t *de =
            disp_lookup (d, g->nh->disp_id, h.sender, h.proto);

          if (!de)
            {
              d->stats.drop_no_entry++;
              continue;
            }

          if (emit (ctx, de->addr, de->port,
                    pkt + BIER_BITSTRING_OFFSET + nbytes,
                    len - BIER_BITSTRING_OFFSET - nbytes) == 0)
            {
              d->stats.tx++;
              d->stats.disposed++;
            }
          continue;
        }

      memcpy (out, pkt, len);
      write_be32 (out, bier_bift_wire_set_ttl (wire, out_ttl));
      memcpy (out + BIER_BITSTRING_OFFSET, g->mask, nbytes);

      if (emit (ctx, g->nh->addr, g->nh->port, out, len) == 0)
        d->stats.tx++;
    }

  rc = 0;

done:
  free (groups);
  free (out);
  return rc;
}

int
bier_impose (bier_domain_t *d, const bier_imp_t *imp, const uint8_t *inner,
             size_t len, bier_emit_fn emit, void *ctx)
{
  bier_table_t *t;
  bier_header_t h;
  uint8_t *buf;
  size_t hdr_len, total;
  uint32_t wire;
  int rc;

  if (!d || !imp || !inner || !emit)
    return -1;

  t = bier_domain_find_table_by_id (d, imp->table_id);
  if (!t)
    return -1;

  if (imp->bitstring_len != t->nbytes)
    return -1;

  hdr_len = BIER_HEADER_FIXED_LEN + t->nbytes;
  total = BIER_BIFT_WIRE_LEN + hdr_len + len;

  buf = malloc (total);
  if (!buf)
    return -1;

  memset (&h, 0, sizeof (h));
  h.version = BIER_HEADER_VERSION;
  h.bsl = t->bsl;
  h.entropy = imp->entropy ? imp->entropy : fnv1a_entropy (inner, len);
  h.proto = imp->proto;
  h.sender = imp->sender;
  h.bitstring_len = t->nbytes;
  memcpy (h.bitstring, imp->bitstring, t->nbytes);

  /*
   * bier_forward() decrements the TTL before emitting, matching VPP's
   * bier-imp/bier-output pair, so start one above the on-wire default.
   */
  wire = bier_bift_wire_encode (t->set, t->sd, t->bsl,
                                (uint8_t) (BIER_DEFAULT_TTL + 1));
  write_be32 (buf, wire);

  if (bier_header_write (&h, buf + BIER_BIFT_WIRE_LEN, hdr_len) == 0)
    {
      free (buf);
      return -1;
    }

  memcpy (buf + BIER_BIFT_WIRE_LEN + hdr_len, inner, len);
  d->stats.imposed++;

  rc = forward_packet (d, buf, total, emit, ctx, 0);
  free (buf);
  return rc;
}

int
bier_forward (bier_domain_t *d, const uint8_t *pkt, size_t len,
              bier_emit_fn emit, void *ctx)
{
  return forward_packet (d, pkt, len, emit, ctx, 1);
}
