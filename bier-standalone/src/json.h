/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal JSON DOM parser used by the standalone BIER daemon.
 */

#ifndef BIER_JSON_H
#define BIER_JSON_H

#include <stdbool.h>
#include <stddef.h>

typedef enum
{
  JSON_NULL,
  JSON_BOOL,
  JSON_NUMBER,
  JSON_STRING,
  JSON_ARRAY,
  JSON_OBJECT,
} json_type_t;

typedef struct json_value json_value_t;

typedef struct json_pair
{
  char *key;
  json_value_t *value;
  struct json_pair *next;
} json_pair_t;

struct json_value
{
  json_type_t type;
  union
  {
    bool boolean;
    long long number;
    char *string;
    struct
    {
      json_value_t **items;
      size_t count;
    } array;
    json_pair_t *pairs;
  } u;
};

json_value_t *json_parse (const char *text, size_t len, char *err,
                          size_t errlen);
void json_free (json_value_t *v);

json_type_t json_type (const json_value_t *v);
const json_value_t *json_object_get (const json_value_t *obj,
                                     const char *key);
size_t json_array_len (const json_value_t *arr);
const json_value_t *json_array_get (const json_value_t *arr, size_t index);
const char *json_string (const json_value_t *v);
long long json_number (const json_value_t *v, long long fallback);

#endif /* BIER_JSON_H */
