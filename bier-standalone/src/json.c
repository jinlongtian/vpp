/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal JSON parser (subset sufficient for static configuration):
 * objects, arrays, strings, integers, booleans and null.
 */

#include "json.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  const char *s;
  size_t len;
  size_t pos;
  int line;
  char *err;
  size_t errlen;
} parser_t;

static void
perr (parser_t *p, const char *fmt, ...)
{
  va_list ap;
  char msg[256];

  va_start (ap, fmt);
  vsnprintf (msg, sizeof (msg), fmt, ap);
  va_end (ap);

  if (p->err && p->errlen)
    snprintf (p->err, p->errlen, "line %d: %s", p->line, msg);
}

static void
skip_ws (parser_t *p)
{
  while (p->pos < p->len)
    {
      char c = p->s[p->pos];

      if (c == ' ' || c == '\t' || c == '\r')
        {
          p->pos++;
          continue;
        }
      if (c == '\n')
        {
          p->line++;
          p->pos++;
          continue;
        }
      break;
    }
}

static json_value_t *parse_value (parser_t *p);

static int
hex_value (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int
utf8_encode (unsigned cp, char *out)
{
  if (cp <= 0x7f)
    {
      out[0] = (char) cp;
      return 1;
    }
  if (cp <= 0x7ff)
    {
      out[0] = (char) (0xc0 | (cp >> 6));
      out[1] = (char) (0x80 | (cp & 0x3f));
      return 2;
    }
  if (cp <= 0xffff)
    {
      if (cp >= 0xd800 && cp <= 0xdfff)
        return -1;
      out[0] = (char) (0xe0 | (cp >> 12));
      out[1] = (char) (0x80 | ((cp >> 6) & 0x3f));
      out[2] = (char) (0x80 | (cp & 0x3f));
      return 3;
    }
  return -1;
}

static char *
parse_string (parser_t *p)
{
  char *out;
  size_t cap;
  size_t n = 0;

  if (p->pos >= p->len || p->s[p->pos] != '"')
    {
      perr (p, "expected string");
      return NULL;
    }
  p->pos++;

  cap = p->len - p->pos + 1;
  out = malloc (cap);
  if (!out)
    {
      perr (p, "out of memory");
      return NULL;
    }

  while (p->pos < p->len)
    {
      unsigned char c = (unsigned char) p->s[p->pos++];

      if (c == '"')
        {
          out[n] = '\0';
          return out;
        }

      if (c == '\\')
        {
          char esc;

          if (p->pos >= p->len)
            break;
          esc = p->s[p->pos++];
          switch (esc)
            {
            case '"':
            case '\\':
            case '/':
              out[n++] = esc;
              break;
            case 'b':
              out[n++] = '\b';
              break;
            case 'f':
              out[n++] = '\f';
              break;
            case 'n':
              out[n++] = '\n';
              break;
            case 'r':
              out[n++] = '\r';
              break;
            case 't':
              out[n++] = '\t';
              break;
            case 'u':
              {
                unsigned cp = 0;
                int i;

                if (p->pos + 4 > p->len)
                  {
                    free (out);
                    perr (p, "truncated \\u escape");
                    return NULL;
                  }
                for (i = 0; i < 4; i++)
                  {
                    int hv = hex_value (p->s[p->pos++]);

                    if (hv < 0)
                      {
                        free (out);
                        perr (p, "invalid \\u escape");
                        return NULL;
                      }
                    cp = (cp << 4) | (unsigned) hv;
                  }
                {
                  int used = utf8_encode (cp, out + n);

                  if (used < 0)
                    {
                      free (out);
                      perr (p, "unsupported unicode escape");
                      return NULL;
                    }
                  n += (size_t) used;
                }
              }
              break;
            default:
              free (out);
              perr (p, "invalid escape '\\%c'", esc);
              return NULL;
            }
          continue;
        }

      if (c < 0x20)
        {
          free (out);
          perr (p, "control character in string");
          return NULL;
        }
      out[n++] = (char) c;
    }

  free (out);
  perr (p, "unterminated string");
  return NULL;
}

static json_value_t *
parse_number (parser_t *p)
{
  char tmp[64];
  size_t n = 0;
  char *end = NULL;
  long long v;
  json_value_t *val;

  while (p->pos < p->len && n + 1 < sizeof (tmp))
    {
      char c = p->s[p->pos];

      if ((c >= '0' && c <= '9') || c == '-' || c == '+')
        {
          tmp[n++] = c;
          p->pos++;
          continue;
        }
      break;
    }

  if (n == 0)
    {
      perr (p, "expected number");
      return NULL;
    }

  tmp[n] = '\0';
  errno = 0;
  v = strtoll (tmp, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    {
      perr (p, "invalid integer '%s'", tmp);
      return NULL;
    }

  val = calloc (1, sizeof (*val));
  if (!val)
    {
      perr (p, "out of memory");
      return NULL;
    }
  val->type = JSON_NUMBER;
  val->u.number = v;
  return val;
}

static json_value_t *
parse_array (parser_t *p)
{
  json_value_t *arr;
  size_t cap = 8;

  p->pos++; /* '[' */
  arr = calloc (1, sizeof (*arr));
  if (!arr)
    {
      perr (p, "out of memory");
      return NULL;
    }
  arr->type = JSON_ARRAY;
  arr->u.array.items = calloc (cap, sizeof (*arr->u.array.items));
  if (!arr->u.array.items)
    {
      free (arr);
      perr (p, "out of memory");
      return NULL;
    }

  for (;;)
    {
      json_value_t *item;

      skip_ws (p);
      if (p->pos >= p->len)
        {
          perr (p, "unterminated array");
          goto fail;
        }
      if (p->s[p->pos] == ']')
        {
          p->pos++;
          return arr;
        }

      item = parse_value (p);
      if (!item)
        goto fail;

      if (arr->u.array.count == cap)
        {
          json_value_t **items;

          cap *= 2;
          items = realloc (arr->u.array.items, cap * sizeof (*items));
          if (!items)
            {
              json_free (item);
              perr (p, "out of memory");
              goto fail;
            }
          arr->u.array.items = items;
        }
      arr->u.array.items[arr->u.array.count++] = item;

      skip_ws (p);
      if (p->pos < p->len && p->s[p->pos] == ',')
        {
          p->pos++;
          continue;
        }
      if (p->pos < p->len && p->s[p->pos] == ']')
        {
          p->pos++;
          return arr;
        }
      perr (p, "expected ',' or ']'");
      goto fail;
    }

fail:
  json_free (arr);
  return NULL;
}

static json_value_t *
parse_object (parser_t *p)
{
  json_value_t *obj;

  p->pos++; /* '{' */
  obj = calloc (1, sizeof (*obj));
  if (!obj)
    {
      perr (p, "out of memory");
      return NULL;
    }
  obj->type = JSON_OBJECT;

  for (;;)
    {
      char *key;
      json_value_t *val;
      json_pair_t *pair;
      json_pair_t **tail;

      skip_ws (p);
      if (p->pos >= p->len)
        {
          perr (p, "unterminated object");
          goto fail;
        }
      if (p->s[p->pos] == '}')
        {
          p->pos++;
          return obj;
        }

      key = parse_string (p);
      if (!key)
        goto fail;

      skip_ws (p);
      if (p->pos >= p->len || p->s[p->pos] != ':')
        {
          free (key);
          perr (p, "expected ':'");
          goto fail;
        }
      p->pos++;

      val = parse_value (p);
      if (!val)
        {
          free (key);
          goto fail;
        }

      pair = calloc (1, sizeof (*pair));
      if (!pair)
        {
          free (key);
          json_free (val);
          perr (p, "out of memory");
          goto fail;
        }
      pair->key = key;
      pair->value = val;

      tail = &obj->u.pairs;
      while (*tail)
        tail = &(*tail)->next;
      *tail = pair;

      skip_ws (p);
      if (p->pos < p->len && p->s[p->pos] == ',')
        {
          p->pos++;
          continue;
        }
      if (p->pos < p->len && p->s[p->pos] == '}')
        {
          p->pos++;
          return obj;
        }
      perr (p, "expected ',' or '}'");
      goto fail;
    }

fail:
  json_free (obj);
  return NULL;
}

static json_value_t *
parse_value (parser_t *p)
{
  char c;

  skip_ws (p);
  if (p->pos >= p->len)
    {
      perr (p, "unexpected end of input");
      return NULL;
    }

  c = p->s[p->pos];
  if (c == '{')
    return parse_object (p);
  if (c == '[')
    return parse_array (p);
  if (c == '"')
    {
      char *s = parse_string (p);
      json_value_t *v;

      if (!s)
        return NULL;
      v = calloc (1, sizeof (*v));
      if (!v)
        {
          free (s);
          perr (p, "out of memory");
          return NULL;
        }
      v->type = JSON_STRING;
      v->u.string = s;
      return v;
    }
  if (c == '-' || (c >= '0' && c <= '9'))
    return parse_number (p);
  if (p->pos + 4 <= p->len && !strncmp (p->s + p->pos, "true", 4))
    {
      json_value_t *v = calloc (1, sizeof (*v));

      if (!v)
        {
          perr (p, "out of memory");
          return NULL;
        }
      p->pos += 4;
      v->type = JSON_BOOL;
      v->u.boolean = true;
      return v;
    }
  if (p->pos + 5 <= p->len && !strncmp (p->s + p->pos, "false", 5))
    {
      json_value_t *v = calloc (1, sizeof (*v));

      if (!v)
        {
          perr (p, "out of memory");
          return NULL;
        }
      p->pos += 5;
      v->type = JSON_BOOL;
      v->u.boolean = false;
      return v;
    }
  if (p->pos + 4 <= p->len && !strncmp (p->s + p->pos, "null", 4))
    {
      json_value_t *v = calloc (1, sizeof (*v));

      if (!v)
        {
          perr (p, "out of memory");
          return NULL;
        }
      p->pos += 4;
      v->type = JSON_NULL;
      return v;
    }

  perr (p, "unexpected character '%c'", c);
  return NULL;
}

json_value_t *
json_parse (const char *text, size_t len, char *err, size_t errlen)
{
  parser_t p;
  json_value_t *root;

  memset (&p, 0, sizeof (p));
  p.s = text;
  p.len = len;
  p.line = 1;
  p.err = err;
  p.errlen = errlen;
  if (err && errlen)
    err[0] = '\0';

  root = parse_value (&p);
  if (!root)
    return NULL;

  skip_ws (&p);
  if (p.pos != p.len)
    {
      perr (&p, "trailing characters after value");
      json_free (root);
      return NULL;
    }
  return root;
}

void
json_free (json_value_t *v)
{
  if (!v)
    return;

  switch (v->type)
    {
    case JSON_STRING:
      free (v->u.string);
      break;
    case JSON_ARRAY:
      {
        size_t i;

        for (i = 0; i < v->u.array.count; i++)
          json_free (v->u.array.items[i]);
        free (v->u.array.items);
      }
      break;
    case JSON_OBJECT:
      {
        json_pair_t *pair = v->u.pairs;

        while (pair)
          {
            json_pair_t *next = pair->next;

            free (pair->key);
            json_free (pair->value);
            free (pair);
            pair = next;
          }
      }
      break;
    default:
      break;
    }
  free (v);
}

json_type_t
json_type (const json_value_t *v)
{
  return v ? v->type : JSON_NULL;
}

const json_value_t *
json_object_get (const json_value_t *obj, const char *key)
{
  json_pair_t *pair;

  if (!obj || obj->type != JSON_OBJECT || !key)
    return NULL;

  for (pair = obj->u.pairs; pair; pair = pair->next)
    if (!strcmp (pair->key, key))
      return pair->value;
  return NULL;
}

size_t
json_array_len (const json_value_t *arr)
{
  if (!arr || arr->type != JSON_ARRAY)
    return 0;
  return arr->u.array.count;
}

const json_value_t *
json_array_get (const json_value_t *arr, size_t index)
{
  if (!arr || arr->type != JSON_ARRAY || index >= arr->u.array.count)
    return NULL;
  return arr->u.array.items[index];
}

const char *
json_string (const json_value_t *v)
{
  if (!v || v->type != JSON_STRING)
    return NULL;
  return v->u.string;
}

long long
json_number (const json_value_t *v, long long fallback)
{
  if (!v || v->type != JSON_NUMBER)
    return fallback;
  return v->u.number;
}
