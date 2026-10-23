/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * BIER wire codec and bit-string helpers.
 *
 * Bit ordering follows RFC 8279: bit-position 1 is the least significant bit
 * of the last byte of the bit-string.
 */

#include "bier/bier.h"

#include <string.h>

static inline uint32_t
read_be32 (const uint8_t *p)
{
  return (((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
          ((uint32_t) p[2] << 8) | (uint32_t) p[3]);
}

static inline uint16_t
read_be16 (const uint8_t *p)
{
  return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

static inline void
write_be32 (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) v;
}

static inline void
write_be16 (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

size_t
bier_bsl_bytes (bier_bsl_t bsl)
{
  switch (bsl)
    {
    case BIER_BSL_64:
      return 8;
    case BIER_BSL_128:
      return 16;
    case BIER_BSL_256:
      return 32;
    case BIER_BSL_512:
      return 64;
    case BIER_BSL_1024:
      return 128;
    case BIER_BSL_2048:
      return 256;
    case BIER_BSL_4096:
      return 512;
    default:
      return 0;
    }
}

uint32_t
bier_bsl_bits (bier_bsl_t bsl)
{
  return (uint32_t) (bier_bsl_bytes (bsl) * 8);
}

bier_bsl_t
bier_bsl_from_bits (uint32_t bits)
{
  switch (bits)
    {
    case 64:
      return BIER_BSL_64;
    case 128:
      return BIER_BSL_128;
    case 256:
      return BIER_BSL_256;
    case 512:
      return BIER_BSL_512;
    case 1024:
      return BIER_BSL_1024;
    case 2048:
      return BIER_BSL_2048;
    case 4096:
      return BIER_BSL_4096;
    default:
      return BIER_BSL_INVALID;
    }
}

uint32_t
bier_bift_id_encode (uint8_t set, uint8_t sd, bier_bsl_t bsl)
{
  return (((uint32_t) bsl << 16) | ((uint32_t) sd << 8) | (uint32_t) set);
}

void
bier_bift_id_decode (uint32_t id, uint8_t *set, uint8_t *sd, bier_bsl_t *bsl)
{
  if (set)
    *set = (uint8_t) (id & 0xff);
  if (sd)
    *sd = (uint8_t) ((id >> 8) & 0xff);
  if (bsl)
    *bsl = (bier_bsl_t) ((id >> 16) & 0x7);
}

uint32_t
bier_bift_wire_encode (uint8_t set, uint8_t sd, bier_bsl_t bsl, uint8_t ttl)
{
  uint32_t id = bier_bift_id_encode (set, sd, bsl);

  /* MPLS label stack entry layout: label(20) | TC(3) | S(1) | TTL(8). */
  return ((id << 12) | (1u << 8) | (uint32_t) ttl);
}

bool
bier_bift_wire_decode (uint32_t wire, uint8_t *set, uint8_t *sd,
                       bier_bsl_t *bsl, uint8_t *ttl)
{
  uint32_t id = (wire >> 12) & 0xfffff;
  bier_bsl_t b;

  if (id >> 19)
    return false;

  b = (bier_bsl_t) ((id >> 16) & 0x7);
  if (b > BIER_BSL_4096)
    return false;

  if (set)
    *set = (uint8_t) (id & 0xff);
  if (sd)
    *sd = (uint8_t) ((id >> 8) & 0xff);
  if (bsl)
    *bsl = b;
  if (ttl)
    *ttl = (uint8_t) (wire & 0xff);
  return true;
}

uint32_t
bier_bift_wire_set_ttl (uint32_t wire, uint8_t ttl)
{
  return ((wire & ~0xffu) | (uint32_t) ttl);
}

uint8_t
bier_bift_wire_get_ttl (uint32_t wire)
{
  return (uint8_t) (wire & 0xff);
}

size_t
bier_header_wire_len (const bier_header_t *h)
{
  size_t nbytes = bier_bsl_bytes (h->bsl);

  if (nbytes == 0)
    return 0;
  return (BIER_HEADER_FIXED_LEN + nbytes);
}

int
bier_header_parse (const uint8_t *buf, size_t len, bier_header_t *h)
{
  uint32_t first;
  uint16_t word2;
  uint8_t version, bsl_id;
  size_t nbytes;

  if (len < BIER_HEADER_FIXED_LEN)
    return -1;

  first = read_be32 (buf);
  word2 = read_be16 (buf + 4);

  version = (uint8_t) ((first >> 24) & 0xf);
  bsl_id = (uint8_t) ((first >> 20) & 0xf);
  if (bsl_id > BIER_BSL_4096)
    return -1;

  nbytes = bier_bsl_bytes ((bier_bsl_t) bsl_id);
  if (nbytes == 0 || len < BIER_HEADER_FIXED_LEN + nbytes)
    return -1;

  memset (h, 0, sizeof (*h));
  h->version = version;
  h->bsl = (bier_bsl_t) bsl_id;
  h->entropy = first & 0xfffffu;
  h->proto = (uint8_t) (word2 & 0x3f);
  h->sender = read_be16 (buf + 6);
  h->bitstring_len = nbytes;
  memcpy (h->bitstring, buf + BIER_HEADER_FIXED_LEN, nbytes);
  return 0;
}

size_t
bier_header_write (const bier_header_t *h, uint8_t *buf, size_t cap)
{
  size_t nbytes = bier_bsl_bytes (h->bsl);
  size_t need;
  uint32_t first;
  uint16_t word2;

  if (nbytes == 0)
    return 0;

  need = BIER_HEADER_FIXED_LEN + nbytes;
  if (cap < need)
    return 0;

  first = ((0x5u << 28) | ((uint32_t) (h->version & 0xf) << 24) |
           ((uint32_t) h->bsl << 20) | (h->entropy & 0xfffffu));
  word2 = (uint16_t) (h->proto & 0x3f);

  write_be32 (buf, first);
  write_be16 (buf + 4, word2);
  write_be16 (buf + 6, h->sender);
  memcpy (buf + BIER_HEADER_FIXED_LEN, h->bitstring, nbytes);
  return need;
}

void
bier_bs_zero (uint8_t *bs, size_t len)
{
  memset (bs, 0, len);
}

void
bier_bs_set (uint8_t *bs, size_t len, uint32_t bp)
{
  uint32_t index;
  uint32_t bit;

  if (bp == 0 || bp > len * 8)
    return;

  index = (uint32_t) (len - 1 - ((bp - 1) / 8));
  bit = (bp - 1) % 8;
  bs[index] |= (uint8_t) (1u << bit);
}

void
bier_bs_clear (uint8_t *bs, size_t len, uint32_t bp)
{
  uint32_t index;
  uint32_t bit;

  if (bp == 0 || bp > len * 8)
    return;

  index = (uint32_t) (len - 1 - ((bp - 1) / 8));
  bit = (bp - 1) % 8;
  bs[index] &= (uint8_t) ~(1u << bit);
}

bool
bier_bs_test (const uint8_t *bs, size_t len, uint32_t bp)
{
  uint32_t index;
  uint32_t bit;

  if (bp == 0 || bp > len * 8)
    return false;

  index = (uint32_t) (len - 1 - ((bp - 1) / 8));
  bit = (bp - 1) % 8;
  return ((bs[index] & (uint8_t) (1u << bit)) != 0);
}

uint32_t
bier_bs_first (const uint8_t *bs, size_t len)
{
  size_t i;

  /*
   * Scan from the last byte backwards so the lowest bit-position is
   * returned first.
   */
  for (i = len; i-- > 0;)
    {
      uint8_t byte = bs[i];

      if (byte != 0)
        {
          uint32_t bit = (uint32_t) __builtin_ctz ((unsigned) byte);
          return (uint32_t) ((len - 1 - i) * 8 + bit + 1);
        }
    }
  return 0;
}

uint32_t
bier_bs_count (const uint8_t *bs, size_t len)
{
  uint32_t n = 0;
  size_t i;

  for (i = 0; i < len; i++)
    n += (uint32_t) __builtin_popcount ((unsigned) bs[i]);
  return n;
}

void
bier_bs_and (uint8_t *dst, const uint8_t *src, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    dst[i] &= src[i];
}
