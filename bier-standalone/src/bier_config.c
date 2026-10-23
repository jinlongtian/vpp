/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Static JSON configuration loader.
 */

#include "bier/bier.h"
#include "json.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
set_err (char *err, size_t errlen, const char *fmt, ...)
{
  va_list ap;

  if (!err || !errlen)
    return;
  va_start (ap, fmt);
  vsnprintf (err, errlen, fmt, ap);
  va_end (ap);
}

static char *
read_file (const char *path, size_t *out_len)
{
  FILE *f;
  long size;
  char *buf;

  f = fopen (path, "rb");
  if (!f)
    return NULL;

  if (fseek (f, 0, SEEK_END) != 0)
    {
      fclose (f);
      return NULL;
    }
  size = ftell (f);
  if (size < 0 || fseek (f, 0, SEEK_SET) != 0)
    {
      fclose (f);
      return NULL;
    }

  buf = malloc ((size_t) size + 1);
  if (!buf)
    {
      fclose (f);
      return NULL;
    }

  if (size > 0 && fread (buf, 1, (size_t) size, f) != (size_t) size)
    {
      free (buf);
      fclose (f);
      return NULL;
    }

  buf[size] = '\0';
  fclose (f);
  *out_len = (size_t) size;
  return buf;
}

static int
parse_endpoint (const char *s, uint32_t *addr, uint16_t *port)
{
  const char *colon;
  char host[128];
  size_t host_len;
  char *end = NULL;
  long p;
  struct in_addr in;

  if (!s)
    return -1;

  colon = strrchr (s, ':');
  if (!colon)
    return -1;

  host_len = (size_t) (colon - s);
  if (host_len == 0 || host_len >= sizeof (host))
    return -1;

  memcpy (host, s, host_len);
  host[host_len] = '\0';

  if (inet_pton (AF_INET, host, &in) != 1)
    return -1;

  errno = 0;
  p = strtol (colon + 1, &end, 10);
  if (errno != 0 || !end || *end != '\0' || p <= 0 || p > 65535)
    return -1;

  *addr = in.s_addr;
  *port = (uint16_t) p;
  return 0;
}

static int
parse_hex_bits (const char *s, uint8_t *out, size_t nbytes)
{
  size_t nibbles = 0;
  int high = -1;

  if (!s)
    return -1;

  memset (out, 0, nbytes);

  for (; *s; s++)
    {
      int v;

      if (*s == ':' || *s == ' ' || *s == '\t' || *s == '\n')
        continue;

      if (*s >= '0' && *s <= '9')
        v = *s - '0';
      else if (*s >= 'a' && *s <= 'f')
        v = *s - 'a' + 10;
      else if (*s >= 'A' && *s <= 'F')
        v = *s - 'A' + 10;
      else
        return -1;

      if (high < 0)
        {
          high = v;
        }
      else
        {
          size_t index = nibbles / 2;

          if (index >= nbytes)
            return -1;
          out[index] = (uint8_t) ((high << 4) | v);
          high = -1;
          nibbles += 2;
        }
    }

  if (high >= 0)
    return -1;
  return nibbles == nbytes * 2 ? 0 : -1;
}

static int
opt_int (const json_value_t *obj, const char *key, long long *out)
{
  const json_value_t *v = json_object_get (obj, key);

  if (!v)
    return 0;
  if (json_type (v) != JSON_NUMBER)
    return -1;
  *out = json_number (v, 0);
  return 1;
}

static int
req_int (const json_value_t *obj, const char *key, long long *out)
{
  int r = opt_int (obj, key, out);

  return r == 1 ? 0 : -1;
}

static int
parse_table (bier_domain_t *d, const json_value_t *jt, size_t index,
             char *err, size_t errlen)
{
  long long id, set, sd, bsl_bits = 256;
  const json_value_t *entries;
  bier_table_t *t;
  size_t i;

  if (json_type (jt) != JSON_OBJECT)
    {
      set_err (err, errlen, "tables[%zu]: expected object", index);
      return -1;
    }

  if (req_int (jt, "id", &id) || req_int (jt, "set", &set) ||
      req_int (jt, "sd", &sd))
    {
      set_err (err, errlen, "tables[%zu]: id/set/sd are required integers",
               index);
      return -1;
    }

  if (opt_int (jt, "bsl", &bsl_bits) < 0)
    {
      set_err (err, errlen, "tables[%zu]: bsl must be an integer", index);
      return -1;
    }

  if (set < 0 || set > 255 || sd < 0 || sd > 255 || id < 0 ||
      id > 0xffffffffLL)
    {
      set_err (err, errlen, "tables[%zu]: id/set/sd out of range", index);
      return -1;
    }

  {
    bier_bsl_t bsl = bier_bsl_from_bits ((uint32_t) bsl_bits);
    bier_table_t *it;

    if (bsl == BIER_BSL_INVALID)
      {
        set_err (err, errlen,
                 "tables[%zu]: invalid bsl (use 64/128/256/512/1024/2048/4096)",
                 index);
        return -1;
      }

    if (bier_domain_find_table_by_id (d, (uint32_t) id))
      {
        set_err (err, errlen, "tables[%zu]: duplicate id %lld", index, id);
        return -1;
      }

    for (it = d->tables; it; it = it->next)
      {
        if (it->set == (uint8_t) set && it->sd == (uint8_t) sd &&
            it->bsl == bsl)
          {
            set_err (err, errlen,
                     "tables[%zu]: duplicate (set=%lld,sd=%lld,bsl=%lld)",
                     index, set, sd, bsl_bits);
            return -1;
          }
      }

    t = bier_domain_add_table (d, (uint32_t) id, (uint8_t) set, (uint8_t) sd,
                               bsl);
    if (!t)
      {
        set_err (err, errlen, "tables[%zu]: out of memory", index);
        return -1;
      }
  }

  entries = json_object_get (jt, "entries");
  if (entries && json_type (entries) != JSON_ARRAY)
    {
      set_err (err, errlen, "tables[%zu].entries: expected array", index);
      return -1;
    }

  for (i = 0; i < json_array_len (entries); i++)
    {
      const json_value_t *je = json_array_get (entries, i);
      const json_value_t *nhs;
      bier_entry_t *e;
      long long bp;
      size_t j;

      if (json_type (je) != JSON_OBJECT || req_int (je, "bp", &bp))
        {
          set_err (err, errlen,
                   "tables[%zu].entries[%zu]: bp is required", index, i);
          return -1;
        }

      if (bp <= 0 || bp > (long long) t->bits)
        {
          set_err (err, errlen,
                   "tables[%zu].entries[%zu]: bp %lld out of range 1..%u",
                   index, i, bp, t->bits);
          return -1;
        }

      e = bier_table_add_entry (t, (uint16_t) bp);
      if (!e)
        {
          set_err (err, errlen, "tables[%zu].entries[%zu]: out of memory",
                   index, i);
          return -1;
        }

      nhs = json_object_get (je, "nexthops");
      if (!nhs || json_type (nhs) != JSON_ARRAY ||
          json_array_len (nhs) == 0)
        {
          set_err (err, errlen,
                   "tables[%zu].entries[%zu].nexthops: non-empty array "
                   "required",
                   index, i);
          return -1;
        }

      for (j = 0; j < json_array_len (nhs); j++)
        {
          const json_value_t *jnh = json_array_get (nhs, j);
          const json_value_t *jdisp;
          long long disp;

          if (json_type (jnh) != JSON_OBJECT)
            {
              set_err (err, errlen,
                       "tables[%zu].entries[%zu].nexthops[%zu]: expected "
                       "object",
                       index, i, j);
              return -1;
            }

          jdisp = json_object_get (jnh, "disp");
          if (jdisp)
            {
              if (json_type (jdisp) != JSON_NUMBER)
                {
                  set_err (err, errlen,
                           "tables[%zu].entries[%zu].nexthops[%zu].disp: "
                           "expected integer",
                           index, i, j);
                  return -1;
                }
              disp = json_number (jdisp, 0);
              if (disp < 0 || disp > 0xffffffffLL ||
                  !bier_entry_add_disp_nexthop (e, (int32_t) disp))
                {
                  set_err (err, errlen,
                           "tables[%zu].entries[%zu].nexthops[%zu]: invalid "
                           "disp",
                           index, i, j);
                  return -1;
                }
            }
          else
            {
              const char *addr =
                json_string (json_object_get (jnh, "addr"));
              uint32_t a;
              uint16_t p;

              if (!addr || parse_endpoint (addr, &a, &p) != 0)
                {
                  set_err (err, errlen,
                           "tables[%zu].entries[%zu].nexthops[%zu]: addr "
                           "must be \"ip:port\"",
                           index, i, j);
                  return -1;
                }
              if (!bier_entry_add_nexthop (e, a, p))
                {
                  set_err (err, errlen,
                           "tables[%zu].entries[%zu].nexthops[%zu]: out of "
                           "memory",
                           index, i, j);
                  return -1;
                }
            }
        }
    }

  return 0;
}

static int
parse_dispositions (bier_domain_t *d, const json_value_t *arr, char *err,
                    size_t errlen)
{
  size_t i;

  for (i = 0; i < json_array_len (arr); i++)
    {
      const json_value_t *jd = json_array_get (arr, i);
      const json_value_t *entries;
      long long id;
      bier_disp_table_t *dt;
      size_t j;

      if (json_type (jd) != JSON_OBJECT || req_int (jd, "id", &id) ||
          id < 0 || id > 0xffffffffLL)
        {
          set_err (err, errlen, "dispositions[%zu]: invalid id", i);
          return -1;
        }

      if (bier_domain_find_disp_table (d, (uint32_t) id))
        {
          set_err (err, errlen, "dispositions[%zu]: duplicate id %lld", i,
                   id);
          return -1;
        }

      dt = bier_domain_add_disp_table (d, (uint32_t) id);
      if (!dt)
        {
          set_err (err, errlen, "dispositions[%zu]: out of memory", i);
          return -1;
        }

      entries = json_object_get (jd, "entries");
      if (!entries || json_type (entries) != JSON_ARRAY)
        {
          set_err (err, errlen, "dispositions[%zu].entries: expected array",
                   i);
          return -1;
        }

      for (j = 0; j < json_array_len (entries); j++)
        {
          const json_value_t *je = json_array_get (entries, j);
          long long sender = 0, proto = BIER_PROTO_IPV4;
          const char *deliver;
          uint32_t a;
          uint16_t p;

          if (json_type (je) != JSON_OBJECT)
            {
              set_err (err, errlen,
                       "dispositions[%zu].entries[%zu]: expected object", i,
                       j);
              return -1;
            }

          if (opt_int (je, "sender", &sender) < 0 ||
              opt_int (je, "proto", &proto) < 0 || sender < 0 ||
              sender > 65535 || proto < 0 || proto > 255)
            {
              set_err (err, errlen,
                       "dispositions[%zu].entries[%zu]: invalid sender/proto",
                       i, j);
              return -1;
            }

          deliver = json_string (json_object_get (je, "deliver"));
          if (!deliver || parse_endpoint (deliver, &a, &p) != 0)
            {
              set_err (err, errlen,
                       "dispositions[%zu].entries[%zu].deliver: must be "
                       "\"ip:port\"",
                       i, j);
              return -1;
            }

          bier_disp_table_add_entry (dt, (uint16_t) sender, (uint8_t) proto, a,
                                     p);
        }
    }
  return 0;
}

static int
parse_impositions (bier_domain_t *d, const json_value_t *arr, char *err,
                   size_t errlen)
{
  size_t i;

  for (i = 0; i < json_array_len (arr); i++)
    {
      const json_value_t *ji = json_array_get (arr, i);
      long long id, table_id, sender = 0, proto = BIER_PROTO_IPV4, entropy = 0;
      const char *listen, *bits;
      bier_table_t *t;
      bier_imp_t *imp;
      uint32_t a;
      uint16_t p;

      if (json_type (ji) != JSON_OBJECT || req_int (ji, "id", &id) ||
          req_int (ji, "table_id", &table_id) || id < 0 ||
          id > 0xffffffffLL)
        {
          set_err (err, errlen, "impositions[%zu]: invalid id/table_id", i);
          return -1;
        }

      if (opt_int (ji, "sender", &sender) < 0 ||
          opt_int (ji, "proto", &proto) < 0 ||
          opt_int (ji, "entropy", &entropy) < 0 || sender < 0 ||
          sender > 65535 || proto < 0 || proto > 255 || entropy < 0 ||
          entropy > 0xfffff)
        {
          set_err (err, errlen, "impositions[%zu]: invalid sender/proto/"
                   "entropy",
                   i);
          return -1;
        }

      if (bier_domain_find_imposition (d, (uint32_t) id))
        {
          set_err (err, errlen, "impositions[%zu]: duplicate id %lld", i, id);
          return -1;
        }

      t = bier_domain_find_table_by_id (d, (uint32_t) table_id);
      if (!t)
        {
          set_err (err, errlen, "impositions[%zu]: unknown table_id %lld", i,
                   table_id);
          return -1;
        }

      bits = json_string (json_object_get (ji, "bitstring"));
      if (!bits)
        {
          set_err (err, errlen, "impositions[%zu].bitstring: required hex "
                   "string",
                   i);
          return -1;
        }

      listen = json_string (json_object_get (ji, "listen"));
      if (!listen || parse_endpoint (listen, &a, &p) != 0)
        {
          set_err (err, errlen, "impositions[%zu].listen: must be "
                   "\"ip:port\"",
                   i);
          return -1;
        }

      imp = bier_domain_add_imposition (d, (uint32_t) id, (uint32_t) table_id,
                                        (uint16_t) sender);
      if (!imp)
        {
          set_err (err, errlen, "impositions[%zu]: out of memory", i);
          return -1;
        }

      imp->proto = (uint8_t) proto;
      imp->entropy = (uint32_t) entropy;
      imp->listen_addr = a;
      imp->listen_port = p;
      imp->bitstring_len = t->nbytes;

      if (parse_hex_bits (bits, imp->bitstring, t->nbytes) != 0)
        {
          set_err (err, errlen,
                   "impositions[%zu].bitstring: expected %zu hex bytes", i,
                   t->nbytes);
          return -1;
        }
    }
  return 0;
}

static int
validate_references (bier_domain_t *d, char *err, size_t errlen)
{
  bier_table_t *t;

  for (t = d->tables; t; t = t->next)
    {
      uint32_t bp;

      for (bp = 1; bp <= t->bits; bp++)
        {
          bier_entry_t *e = t->bp_map[bp - 1];
          bier_nexthop_t *nh;

          if (!e)
            continue;
          for (nh = e->nhs; nh; nh = nh->next)
            {
              if (nh->disp_id >= 0 &&
                  !bier_domain_find_disp_table (d, (uint32_t) nh->disp_id))
                {
                  set_err (err, errlen,
                           "table %u bp %u references unknown disposition "
                           "%d",
                           t->id, bp, nh->disp_id);
                  return -1;
                }
            }
        }
    }
  return 0;
}

int
bier_config_load (const char *path, bier_domain_t **out, char *err,
                  size_t errlen)
{
  char *text;
  size_t len;
  json_value_t *root;
  bier_domain_t *d;
  const json_value_t *tables, *disps, *imps, *listen;
  size_t i;

  if (err && errlen)
    err[0] = '\0';

  text = read_file (path, &len);
  if (!text)
    {
      set_err (err, errlen, "cannot read %s", path);
      return -1;
    }

  root = json_parse (text, len, err, errlen);
  free (text);
  if (!root)
    return -1;

  if (json_type (root) != JSON_OBJECT)
    {
      set_err (err, errlen, "top-level value must be an object");
      json_free (root);
      return -1;
    }

  d = bier_domain_new ();
  if (!d)
    {
      set_err (err, errlen, "out of memory");
      json_free (root);
      return -1;
    }

  d->listen_port = 8138;
  listen = json_object_get (root, "listen");
  if (listen)
    {
      const char *s = json_string (listen);

      if (!s || parse_endpoint (s, &d->listen_addr, &d->listen_port) != 0)
        {
          set_err (err, errlen, "listen: must be \"ip:port\"");
          goto fail;
        }
    }

  tables = json_object_get (root, "tables");
  if (!tables || json_type (tables) != JSON_ARRAY)
    {
      set_err (err, errlen, "tables: non-empty array required");
      goto fail;
    }

  for (i = 0; i < json_array_len (tables); i++)
    if (parse_table (d, json_array_get (tables, i), i, err, errlen) != 0)
      goto fail;

  disps = json_object_get (root, "dispositions");
  if (disps)
    {
      if (json_type (disps) != JSON_ARRAY)
        {
          set_err (err, errlen, "dispositions: expected array");
          goto fail;
        }
      if (parse_dispositions (d, disps, err, errlen) != 0)
        goto fail;
    }

  imps = json_object_get (root, "impositions");
  if (imps)
    {
      if (json_type (imps) != JSON_ARRAY)
        {
          set_err (err, errlen, "impositions: expected array");
          goto fail;
        }
      if (parse_impositions (d, imps, err, errlen) != 0)
        goto fail;
    }

  if (validate_references (d, err, errlen) != 0)
    goto fail;

  json_free (root);
  *out = d;
  return 0;

fail:
  bier_domain_free (d);
  json_free (root);
  return -1;
}
