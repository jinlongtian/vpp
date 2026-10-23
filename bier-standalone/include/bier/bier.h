/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone BIER forwarding library.
 *
 * The wire format and bit ordering follow RFC 8279 / RFC 8296 and are
 * derived from the FD.io VPP BIER implementation.
 */

#ifndef BIER_BIER_H
#define BIER_BIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BIER_HEADER_VERSION 0
#define BIER_HEADER_FIXED_LEN 8
#define BIER_BIFT_WIRE_LEN 4
#define BIER_MAX_BSL_BITS 4096
#define BIER_MAX_BSL_BYTES (BIER_MAX_BSL_BITS / 8)
#define BIER_DEFAULT_TTL 64
#define BIER_PROTO_ANY 0xff

typedef enum
{
  BIER_BSL_64 = 0,
  BIER_BSL_128 = 1,
  BIER_BSL_256 = 2,
  BIER_BSL_512 = 3,
  BIER_BSL_1024 = 4,
  BIER_BSL_2048 = 5,
  BIER_BSL_4096 = 6,
  BIER_BSL_INVALID = 7,
} bier_bsl_t;

typedef enum
{
  BIER_PROTO_INVALID = 0,
  BIER_PROTO_MPLS_DOWNSTREAM = 1,
  BIER_PROTO_MPLS_UPSTREAM = 2,
  BIER_PROTO_ETHERNET = 3,
  BIER_PROTO_IPV4 = 4,
  BIER_PROTO_IPV6 = 5,
  BIER_PROTO_VXLAN = 6,
  BIER_PROTO_CONTROL = 7,
  BIER_PROTO_OAM = 8,
} bier_proto_t;

/*
 * A parsed BIER header.  All fields are in host byte order; the bit-string is
 * kept in wire order (MSB first, bit-position 1 is the LSB of the last byte).
 */
typedef struct
{
  uint8_t version;
  bier_bsl_t bsl;
  uint32_t entropy;
  uint8_t proto;
  uint16_t sender;
  uint8_t bitstring[BIER_MAX_BSL_BYTES];
  size_t bitstring_len;
} bier_header_t;

/* ------------------------------------------------------------------ */
/* Codec                                                               */
/* ------------------------------------------------------------------ */

size_t bier_bsl_bytes (bier_bsl_t bsl);
uint32_t bier_bsl_bits (bier_bsl_t bsl);
bier_bsl_t bier_bsl_from_bits (uint32_t bits);

uint32_t bier_bift_id_encode (uint8_t set, uint8_t sd, bier_bsl_t bsl);
void bier_bift_id_decode (uint32_t id, uint8_t *set, uint8_t *sd,
                          bier_bsl_t *bsl);

uint32_t bier_bift_wire_encode (uint8_t set, uint8_t sd, bier_bsl_t bsl,
                                uint8_t ttl);
bool bier_bift_wire_decode (uint32_t wire, uint8_t *set, uint8_t *sd,
                            bier_bsl_t *bsl, uint8_t *ttl);
uint32_t bier_bift_wire_set_ttl (uint32_t wire, uint8_t ttl);
uint8_t bier_bift_wire_get_ttl (uint32_t wire);

size_t bier_header_wire_len (const bier_header_t *h);
int bier_header_parse (const uint8_t *buf, size_t len, bier_header_t *h);
size_t bier_header_write (const bier_header_t *h, uint8_t *buf, size_t cap);

/* ------------------------------------------------------------------ */
/* Bit-string helpers                                                  */
/* ------------------------------------------------------------------ */

void bier_bs_zero (uint8_t *bs, size_t len);
void bier_bs_set (uint8_t *bs, size_t len, uint32_t bp);
void bier_bs_clear (uint8_t *bs, size_t len, uint32_t bp);
bool bier_bs_test (const uint8_t *bs, size_t len, uint32_t bp);
uint32_t bier_bs_first (const uint8_t *bs, size_t len);
uint32_t bier_bs_count (const uint8_t *bs, size_t len);
void bier_bs_and (uint8_t *dst, const uint8_t *src, size_t len);

/* ------------------------------------------------------------------ */
/* Forwarding domain                                                   */
/* ------------------------------------------------------------------ */

/*
 * A next-hop is either a remote UDP endpoint (disp_id < 0) or a local
 * disposition table (disp_id >= 0).
 */
typedef struct bier_nexthop
{
  uint32_t addr;        /* IPv4 address in network byte order */
  uint16_t port;        /* host byte order */
  int32_t disp_id;      /* >= 0 selects a local disposition table */
  struct bier_nexthop *next;
} bier_nexthop_t;

typedef struct bier_entry
{
  uint16_t bp;
  bier_nexthop_t *nhs;
  uint32_t n_nh;
  uint64_t pkts;
} bier_entry_t;

typedef struct bier_table
{
  uint32_t id;
  uint8_t set;
  uint8_t sd;
  bier_bsl_t bsl;
  size_t nbytes;
  uint32_t bits;
  bier_entry_t **bp_map; /* indexed by bp - 1 */
  uint32_t n_entries;
  struct bier_table *next;
} bier_table_t;

typedef struct bier_disp_entry
{
  uint16_t sender; /* 0 = default */
  uint8_t proto;   /* BIER_PROTO_ANY = wildcard */
  uint32_t addr;
  uint16_t port;
  struct bier_disp_entry *next;
} bier_disp_entry_t;

typedef struct bier_disp_table
{
  uint32_t id;
  bier_disp_entry_t *entries;
  struct bier_disp_table *next;
} bier_disp_table_t;

typedef struct bier_imp
{
  uint32_t id;
  uint32_t table_id;
  uint16_t sender;
  uint8_t proto;
  uint32_t entropy; /* 0 = derive from the inner packet */
  uint8_t bitstring[BIER_MAX_BSL_BYTES];
  size_t bitstring_len;
  uint32_t listen_addr;
  uint16_t listen_port;
  struct bier_imp *next;
} bier_imp_t;

typedef struct
{
  uint64_t rx;
  uint64_t tx;
  uint64_t imposed;
  uint64_t disposed;
  uint64_t drop_no_table;
  uint64_t drop_bad_header;
  uint64_t drop_ttl;
  uint64_t drop_no_entry;
} bier_stats_t;

typedef struct bier_domain
{
  uint32_t listen_addr;
  uint16_t listen_port;
  bier_table_t *tables;
  bier_disp_table_t *disp_tables;
  bier_imp_t *imps;
  bier_stats_t stats;
} bier_domain_t;

bier_domain_t *bier_domain_new (void);
void bier_domain_free (bier_domain_t *d);

bier_table_t *bier_domain_add_table (bier_domain_t *d, uint32_t id,
                                     uint8_t set, uint8_t sd, bier_bsl_t bsl);
bier_table_t *bier_domain_find_table_by_id (const bier_domain_t *d,
                                            uint32_t id);
bier_table_t *bier_domain_find_table_by_bift (const bier_domain_t *d,
                                              uint32_t bift_id);

bier_entry_t *bier_table_add_entry (bier_table_t *t, uint16_t bp);
bier_nexthop_t *bier_entry_add_nexthop (bier_entry_t *e, uint32_t addr,
                                        uint16_t port);
bier_nexthop_t *bier_entry_add_disp_nexthop (bier_entry_t *e, int32_t disp_id);

bier_disp_table_t *bier_domain_add_disp_table (bier_domain_t *d, uint32_t id);
bier_disp_table_t *bier_domain_find_disp_table (const bier_domain_t *d,
                                                uint32_t id);
void bier_disp_table_add_entry (bier_disp_table_t *dt, uint16_t sender,
                                uint8_t proto, uint32_t addr, uint16_t port);

bier_imp_t *bier_domain_add_imposition (bier_domain_t *d, uint32_t id,
                                        uint32_t table_id, uint16_t sender);
bier_imp_t *bier_domain_find_imposition (const bier_domain_t *d, uint32_t id);

/* ------------------------------------------------------------------ */
/* Forwarding API                                                      */
/* ------------------------------------------------------------------ */

/*
 * The emit callback must send/receive the packet synchronously.  Returning
 * non-zero is treated as a send failure.
 */
typedef int (*bier_emit_fn) (void *ctx, uint32_t addr, uint16_t port,
                             const uint8_t *pkt, size_t len);

/*
 * Forward one packet received on the BIER UDP port.  The buffer starts with
 * the 4-byte BIFT field followed by the BIER header.
 */
int bier_forward (bier_domain_t *d, const uint8_t *pkt, size_t len,
                  bier_emit_fn emit, void *ctx);

/*
 * Impose a BIER header on an inner packet and forward it.
 */
int bier_impose (bier_domain_t *d, const bier_imp_t *imp, const uint8_t *inner,
                 size_t len, bier_emit_fn emit, void *ctx);

/* ------------------------------------------------------------------ */
/* JSON configuration                                                  */
/* ------------------------------------------------------------------ */

int bier_config_load (const char *path, bier_domain_t **out, char *err,
                      size_t errlen);

#endif /* BIER_BIER_H */
