/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bier/bier.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, ...)                                                      \
  do                                                                          \
    {                                                                         \
      if (!(cond))                                                            \
        {                                                                     \
          fprintf (stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
          fprintf (stderr, __VA_ARGS__);                                      \
          fputc ('\n', stderr);                                               \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)

typedef struct
{
  uint32_t addr;
  uint16_t port;
  uint8_t data[8192];
  size_t len;
} cap_pkt_t;

typedef struct
{
  cap_pkt_t pkts[16];
  int n;
} capture_t;

static int
emit_cb (void *ctx, uint32_t addr, uint16_t port, const uint8_t *pkt, size_t len)
{
  capture_t *c = ctx;

  if (c->n >= 16 || len > sizeof (c->pkts[0].data))
    return -1;

  c->pkts[c->n].addr = addr;
  c->pkts[c->n].port = port;
  c->pkts[c->n].len = len;
  memcpy (c->pkts[c->n].data, pkt, len);
  c->n++;
  return 0;
}

static uint32_t
addr_of (const char *s)
{
  struct in_addr in;

  if (inet_pton (AF_INET, s, &in) != 1)
    {
      fprintf (stderr, "bad address %s\n", s);
      exit (2);
    }
  return in.s_addr;
}

static void
write_be32 (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) v;
}

static size_t
make_packet (uint8_t *buf, size_t cap, bier_bsl_t bsl, uint8_t set, uint8_t sd,
             uint8_t ttl, uint16_t sender, uint8_t proto, uint32_t entropy,
             const uint8_t *bits, const uint8_t *payload, size_t plen)
{
  bier_header_t h;
  size_t nbytes = bier_bsl_bytes (bsl);
  size_t total = BIER_BIFT_WIRE_LEN + BIER_HEADER_FIXED_LEN + nbytes + plen;

  if (cap < total)
    return 0;

  write_be32 (buf, bier_bift_wire_encode (set, sd, bsl, ttl));

  memset (&h, 0, sizeof (h));
  h.version = BIER_HEADER_VERSION;
  h.bsl = bsl;
  h.entropy = entropy;
  h.proto = proto;
  h.sender = sender;
  h.bitstring_len = nbytes;
  memcpy (h.bitstring, bits, nbytes);

  if (bier_header_write (&h, buf + BIER_BIFT_WIRE_LEN,
                         BIER_HEADER_FIXED_LEN + nbytes) == 0)
    return 0;

  memcpy (buf + BIER_BIFT_WIRE_LEN + BIER_HEADER_FIXED_LEN + nbytes, payload,
          plen);
  return total;
}

static void
test_bift (void)
{
  uint8_t set, sd, ttl;
  bier_bsl_t bsl;
  uint32_t id = bier_bift_id_encode (1, 2, BIER_BSL_256);
  uint32_t wire;

  CHECK (id == ((2u << 16) | (2u << 8) | 1u), "bift id 0x%x", id);

  bier_bift_id_decode (id, &set, &sd, &bsl);
  CHECK (set == 1 && sd == 2 && bsl == BIER_BSL_256, "decode");

  wire = bier_bift_wire_encode (1, 2, BIER_BSL_256, 64);
  CHECK (bier_bift_wire_get_ttl (wire) == 64, "ttl");
  CHECK (bier_bift_wire_decode (wire, &set, &sd, &bsl, &ttl), "wire decode");
  CHECK (set == 1 && sd == 2 && bsl == BIER_BSL_256 && ttl == 64,
         "wire fields");

  wire = bier_bift_wire_set_ttl (wire, 9);
  CHECK (bier_bift_wire_get_ttl (wire) == 9, "ttl rewrite");
}

static void
test_bitstring (void)
{
  uint8_t bs[8];

  bier_bs_zero (bs, sizeof (bs));

  bier_bs_set (bs, sizeof (bs), 1);
  CHECK (bs[7] == 0x01, "bp1 -> last byte lsb, got 0x%02x", bs[7]);
  CHECK (bier_bs_first (bs, sizeof (bs)) == 1, "first bp1");

  bier_bs_set (bs, sizeof (bs), 8);
  CHECK (bs[7] == 0x81, "bp8 -> last byte msb");
  CHECK (bier_bs_test (bs, sizeof (bs), 8), "test bp8");

  bier_bs_set (bs, sizeof (bs), 9);
  CHECK (bs[6] == 0x01, "bp9 -> second last byte lsb");

  CHECK (bier_bs_count (bs, sizeof (bs)) == 3, "count");

  bier_bs_clear (bs, sizeof (bs), 1);
  CHECK (bier_bs_first (bs, sizeof (bs)) == 8, "first after clear");
  CHECK (!bier_bs_test (bs, sizeof (bs), 1), "cleared bp1");
}

static void
test_header (void)
{
  bier_header_t h, parsed;
  uint8_t buf[64];
  size_t n;

  memset (&h, 0, sizeof (h));
  h.version = BIER_HEADER_VERSION;
  h.bsl = BIER_BSL_128;
  h.entropy = 0xabcde;
  h.proto = BIER_PROTO_IPV6;
  h.sender = 333;
  h.bitstring_len = bier_bsl_bytes (BIER_BSL_128);
  bier_bs_set (h.bitstring, h.bitstring_len, 1);
  bier_bs_set (h.bitstring, h.bitstring_len, 128);

  n = bier_header_write (&h, buf, sizeof (buf));
  CHECK (n == BIER_HEADER_FIXED_LEN + h.bitstring_len, "header write length");

  CHECK (bier_header_parse (buf, n, &parsed) == 0, "header parse");
  CHECK (parsed.version == h.version, "version");
  CHECK (parsed.bsl == h.bsl, "bsl");
  CHECK (parsed.entropy == h.entropy, "entropy");
  CHECK (parsed.proto == h.proto, "proto");
  CHECK (parsed.sender == h.sender, "sender");
  CHECK (!memcmp (parsed.bitstring, h.bitstring, h.bitstring_len),
         "bitstring");
  CHECK (bier_bs_test (parsed.bitstring, parsed.bitstring_len, 1), "bp1");
  CHECK (bier_bs_test (parsed.bitstring, parsed.bitstring_len, 128), "bp128");
}

static void
test_forward (void)
{
  bier_domain_t *d = bier_domain_new ();
  bier_table_t *t = bier_domain_add_table (d, 0, 0, 1, BIER_BSL_64);
  bier_entry_t *e;
  uint8_t bits[8] = { 0 };
  uint8_t pkt[1024];
  const char *payload = "payload";
  size_t len;
  capture_t cap = { 0 };

  e = bier_table_add_entry (t, 1);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 1001);
  e = bier_table_add_entry (t, 2);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 1002);
  e = bier_table_add_entry (t, 64);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 1003);

  bier_bs_set (bits, sizeof (bits), 1);
  bier_bs_set (bits, sizeof (bits), 2);
  bier_bs_set (bits, sizeof (bits), 64);

  len = make_packet (pkt, sizeof (pkt), BIER_BSL_64, 0, 1, 10, 333,
                     BIER_PROTO_IPV6, 7, bits,
                     (const uint8_t *) payload, strlen (payload));
  CHECK (len > 0, "packet build");

  CHECK (bier_forward (d, pkt, len, emit_cb, &cap) == 0, "forward rc");
  CHECK (cap.n == 3, "expected 3 outputs, got %d", cap.n);

  for (int i = 0; i < cap.n; i++)
    {
      bier_header_t h;
      uint8_t ttl;
      bier_bsl_t bsl;
      uint8_t set, sd;

      CHECK (bier_bift_wire_decode (
               ((uint32_t) cap.pkts[i].data[0] << 24) |
                 ((uint32_t) cap.pkts[i].data[1] << 16) |
                 ((uint32_t) cap.pkts[i].data[2] << 8) |
                 (uint32_t) cap.pkts[i].data[3],
               &set, &sd, &bsl, &ttl),
             "output bift");
      CHECK (bsl == BIER_BSL_64, "output bsl");
      CHECK (ttl == 9, "output ttl %u", ttl);

      CHECK (bier_header_parse (cap.pkts[i].data + 4,
                                cap.pkts[i].len - 4, &h) == 0,
             "output header");
      CHECK (bier_bs_count (h.bitstring, h.bitstring_len) == 1,
             "one bp per output");
      CHECK (h.sender == 333, "sender preserved");
      CHECK (!memcmp (cap.pkts[i].data + cap.pkts[i].len - strlen (payload),
                      payload, strlen (payload)),
             "payload preserved");
    }

  CHECK (cap.pkts[0].port == 1001 && cap.pkts[1].port == 1002 &&
           cap.pkts[2].port == 1003,
         "next-hop ports");

  bier_domain_free (d);
}

static void
test_disposition (void)
{
  bier_domain_t *d = bier_domain_new ();
  bier_table_t *t = bier_domain_add_table (d, 0, 0, 1, BIER_BSL_64);
  bier_disp_table_t *dt = bier_domain_add_disp_table (d, 8);
  bier_entry_t *e;
  uint8_t bits[8] = { 0 };
  uint8_t pkt[1024];
  const char *inner = "inner-payload";
  size_t len;
  capture_t cap = { 0 };

  e = bier_table_add_entry (t, 3);
  bier_entry_add_disp_nexthop (e, 8);
  bier_disp_table_add_entry (dt, 99, BIER_PROTO_IPV6, addr_of ("127.0.0.1"),
                             2001);

  bier_bs_set (bits, sizeof (bits), 3);
  len = make_packet (pkt, sizeof (pkt), BIER_BSL_64, 0, 1, 10, 99,
                     BIER_PROTO_IPV6, 0, bits, (const uint8_t *) inner,
                     strlen (inner));

  CHECK (bier_forward (d, pkt, len, emit_cb, &cap) == 0, "forward rc");
  CHECK (cap.n == 1, "expected 1 disposition output, got %d", cap.n);
  CHECK (cap.pkts[0].port == 2001, "deliver port");
  CHECK (cap.pkts[0].len == strlen (inner), "payload length");
  CHECK (!memcmp (cap.pkts[0].data, inner, strlen (inner)), "payload content");
  CHECK (d->stats.disposed == 1, "disposed counter");

  bier_domain_free (d);
}

static void
test_impose (void)
{
  bier_domain_t *d = bier_domain_new ();
  bier_table_t *t = bier_domain_add_table (d, 0, 0, 1, BIER_BSL_64);
  bier_entry_t *e;
  bier_imp_t *imp;
  const char *inner = "inner";
  capture_t cap = { 0 };

  e = bier_table_add_entry (t, 1);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 3001);
  e = bier_table_add_entry (t, 2);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 3002);

  imp = bier_domain_add_imposition (d, 1, 0, 333);
  imp->proto = BIER_PROTO_IPV6;
  imp->entropy = 42;
  imp->bitstring_len = bier_bsl_bytes (BIER_BSL_64);
  bier_bs_set (imp->bitstring, imp->bitstring_len, 1);
  bier_bs_set (imp->bitstring, imp->bitstring_len, 2);

  CHECK (bier_impose (d, imp, (const uint8_t *) inner, strlen (inner),
                      emit_cb, &cap) == 0,
         "impose rc");
  CHECK (cap.n == 2, "expected 2 outputs, got %d", cap.n);
  CHECK (d->stats.imposed == 1, "imposed counter");

  for (int i = 0; i < cap.n; i++)
    {
      bier_header_t h;
      uint8_t set, sd, ttl;
      bier_bsl_t bsl;

      CHECK (bier_bift_wire_decode (
               ((uint32_t) cap.pkts[i].data[0] << 24) |
                 ((uint32_t) cap.pkts[i].data[1] << 16) |
                 ((uint32_t) cap.pkts[i].data[2] << 8) |
                 (uint32_t) cap.pkts[i].data[3],
               &set, &sd, &bsl, &ttl),
             "bift");
      CHECK (ttl == BIER_DEFAULT_TTL, "imposed ttl %u", ttl);

      CHECK (bier_header_parse (cap.pkts[i].data + 4,
                                cap.pkts[i].len - 4, &h) == 0,
             "header");
      CHECK (h.sender == 333, "sender");
      CHECK (h.proto == BIER_PROTO_IPV6, "proto");
      CHECK (h.entropy == 42, "entropy");
      CHECK (bier_bs_count (h.bitstring, h.bitstring_len) == 1, "one bp");
    }

  bier_domain_free (d);
}

static void
test_ecmp (void)
{
  bier_domain_t *d = bier_domain_new ();
  bier_table_t *t = bier_domain_add_table (d, 0, 0, 1, BIER_BSL_64);
  bier_entry_t *e;
  uint8_t bits[8] = { 0 };
  uint8_t pkt[256];
  size_t len;
  capture_t cap;

  e = bier_table_add_entry (t, 5);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 4001);
  bier_entry_add_nexthop (e, addr_of ("127.0.0.1"), 4002);

  bier_bs_set (bits, sizeof (bits), 5);

  len = make_packet (pkt, sizeof (pkt), BIER_BSL_64, 0, 1, 10, 1,
                     BIER_PROTO_IPV4, 0, bits, (const uint8_t *) "x", 1);
  memset (&cap, 0, sizeof (cap));
  CHECK (bier_forward (d, pkt, len, emit_cb, &cap) == 0, "forward");
  CHECK (cap.n == 1 && cap.pkts[0].port == 4001, "ecmp path 0");

  len = make_packet (pkt, sizeof (pkt), BIER_BSL_64, 0, 1, 10, 1,
                     BIER_PROTO_IPV4, 1, bits, (const uint8_t *) "x", 1);
  memset (&cap, 0, sizeof (cap));
  CHECK (bier_forward (d, pkt, len, emit_cb, &cap) == 0, "forward");
  CHECK (cap.n == 1 && cap.pkts[0].port == 4002, "ecmp path 1");

  bier_domain_free (d);
}

int
main (void)
{
  test_bift ();
  test_bitstring ();
  test_header ();
  test_forward ();
  test_disposition ();
  test_impose ();
  test_ecmp ();

  if (failures)
    {
      fprintf (stderr, "%d test(s) failed\n", failures);
      return 1;
    }

  printf ("all BIER tests passed\n");
  return 0;
}
