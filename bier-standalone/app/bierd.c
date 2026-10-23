/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * bierd - standalone BIER forwarding daemon (non-MPLS / UDP encapsulation).
 *
 * Wire format on UDP port 8138:
 *   4-byte BIFT field (MPLS-label-like) | BIER header | payload
 */

#include "bier/bier.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_LISTENERS 64
#define RX_BUFSIZE 65536

typedef enum
{
  LISTEN_BIER = 0,
  LISTEN_IMPOSITION = 1,
} listen_kind_t;

typedef struct
{
  int fd;
  listen_kind_t kind;
  bier_imp_t *imp;
} listener_t;

typedef struct
{
  int fd;
} emit_ctx_t;

static volatile sig_atomic_t g_running = 1;
static int g_verbose = 0;

static void
on_signal (int signo)
{
  (void) signo;
  g_running = 0;
}

static void
log_msg (const char *level, const char *fmt, va_list ap)
{
  struct timespec ts;
  struct tm tm;
  char stamp[32];

  clock_gettime (CLOCK_REALTIME, &ts);
  localtime_r (&ts.tv_sec, &tm);
  strftime (stamp, sizeof (stamp), "%Y-%m-%d %H:%M:%S", &tm);

  fprintf (stderr, "%s.%03ld %s: ", stamp, ts.tv_nsec / 1000000, level);
  vfprintf (stderr, fmt, ap);
  fputc ('\n', stderr);
}

static void
log_info (const char *fmt, ...)
{
  va_list ap;

  if (!g_verbose)
    return;
  va_start (ap, fmt);
  log_msg ("INFO", fmt, ap);
  va_end (ap);
}

static void
log_error (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  log_msg ("ERROR", fmt, ap);
  va_end (ap);
}

static void
format_addr (uint32_t addr, char *buf, size_t len)
{
  struct in_addr in;

  in.s_addr = addr;
  if (!inet_ntop (AF_INET, &in, buf, (socklen_t) len))
    snprintf (buf, len, "?");
}

static int
udp_socket (uint32_t addr, uint16_t port)
{
  int fd;
  struct sockaddr_in sa;
  int one = 1;

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;

  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);
  sa.sin_addr.s_addr = addr;

  if (bind (fd, (struct sockaddr *) &sa, sizeof (sa)) != 0)
    {
      close (fd);
      return -1;
    }
  return fd;
}

static int
udp_emit (void *ctx, uint32_t addr, uint16_t port, const uint8_t *pkt,
          size_t len)
{
  emit_ctx_t *e = ctx;
  struct sockaddr_in sa;
  ssize_t n;

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);
  sa.sin_addr.s_addr = addr;

  n = sendto (e->fd, pkt, len, 0, (struct sockaddr *) &sa, sizeof (sa));
  return n == (ssize_t) len ? 0 : -1;
}

static void
show_tables (const bier_domain_t *d)
{
  const bier_table_t *t;

  if (!d->tables)
    {
      printf ("no tables\n");
      return;
    }

  for (t = d->tables; t; t = t->next)
    {
      uint32_t bp;

      printf ("table %u: set=%u sd=%u bsl=%u entries=%u\n", t->id, t->set,
              t->sd, bier_bsl_bits (t->bsl), t->n_entries);

      for (bp = 1; bp <= t->bits; bp++)
        {
          const bier_entry_t *e = t->bp_map[bp - 1];
          const bier_nexthop_t *nh;

          if (!e)
            continue;

          printf ("  bp %u: nexthops=%u pkts=%llu\n", e->bp, e->n_nh,
                  (unsigned long long) e->pkts);

          for (nh = e->nhs; nh; nh = nh->next)
            {
              if (nh->disp_id >= 0)
                printf ("    -> disposition %d\n", nh->disp_id);
              else
                {
                  char abuf[INET_ADDRSTRLEN];

                  format_addr (nh->addr, abuf, sizeof (abuf));
                  printf ("    -> %s:%u\n", abuf, nh->port);
                }
            }
        }
    }
}

static void
show_config (const bier_domain_t *d)
{
  char abuf[INET_ADDRSTRLEN];
  const bier_imp_t *imp;
  const bier_disp_table_t *dt;

  format_addr (d->listen_addr, abuf, sizeof (abuf));
  printf ("listen: %s:%u\n", abuf, d->listen_port);

  for (imp = d->imps; imp; imp = imp->next)
    {
      format_addr (imp->listen_addr, abuf, sizeof (abuf));
      printf ("imposition %u: table=%u sender=%u proto=%u listen=%s:%u "
              "bits=%zu\n",
              imp->id, imp->table_id, imp->sender, imp->proto, abuf,
              imp->listen_port, imp->bitstring_len * 8);
    }

  for (dt = d->disp_tables; dt; dt = dt->next)
    {
      const bier_disp_entry_t *e;
      uint32_t n = 0;

      for (e = dt->entries; e; e = e->next)
        n++;
      printf ("disposition %u: entries=%u\n", dt->id, n);
    }
}

static void
show_stats (const bier_domain_t *d)
{
  const bier_stats_t *s = &d->stats;

  printf ("rx=%llu tx=%llu imposed=%llu disposed=%llu\n",
          (unsigned long long) s->rx, (unsigned long long) s->tx,
          (unsigned long long) s->imposed,
          (unsigned long long) s->disposed);
  printf ("drops: no-table=%llu bad-header=%llu ttl=%llu no-entry=%llu\n",
          (unsigned long long) s->drop_no_table,
          (unsigned long long) s->drop_bad_header,
          (unsigned long long) s->drop_ttl,
          (unsigned long long) s->drop_no_entry);
}

static void
show_help (void)
{
  printf ("commands:\n"
          "  show tables     list BIER tables and next-hops\n"
          "  show config     list listeners and imposition objects\n"
          "  show stats      forwarding counters\n"
          "  help            this text\n"
          "  quit            exit\n");
}

static void
process_cli (char *line, bier_domain_t *d)
{
  size_t len = strlen (line);

  while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
    line[--len] = '\0';

  if (len == 0)
    return;

  if (!strcmp (line, "show tables") || !strcmp (line, "show table"))
    show_tables (d);
  else if (!strcmp (line, "show config"))
    show_config (d);
  else if (!strcmp (line, "show stats"))
    show_stats (d);
  else if (!strcmp (line, "help") || !strcmp (line, "?"))
    show_help ();
  else if (!strcmp (line, "quit") || !strcmp (line, "exit"))
    g_running = 0;
  else
    printf ("unknown command: %s\n", line);
}

static void
usage (const char *prog)
{
  fprintf (stderr,
           "usage: %s -c <config.json> [-v]\n"
           "  -c  static JSON configuration\n"
           "  -v  verbose logging\n"
           "  -h  this help\n",
           prog);
}

int
main (int argc, char **argv)
{
  const char *config_path = NULL;
  bier_domain_t *domain = NULL;
  listener_t listeners[MAX_LISTENERS];
  size_t n_listeners = 0;
  char err[512];
  int opt;
  int bier_fd = -1;
  bier_imp_t *imp;
  emit_ctx_t ectx;
  uint8_t *rxbuf = NULL;
  int stdin_open = 1;

  while ((opt = getopt (argc, argv, "c:vh")) != -1)
    {
      switch (opt)
        {
        case 'c':
          config_path = optarg;
          break;
        case 'v':
          g_verbose = 1;
          break;
        case 'h':
          usage (argv[0]);
          return 0;
        default:
          usage (argv[0]);
          return 1;
        }
    }

  if (!config_path)
    {
      usage (argv[0]);
      return 1;
    }

  if (bier_config_load (config_path, &domain, err, sizeof (err)) != 0)
    {
      log_error ("configuration error: %s", err);
      return 1;
    }

  signal (SIGINT, on_signal);
  signal (SIGTERM, on_signal);

  bier_fd = udp_socket (domain->listen_addr, domain->listen_port);
  if (bier_fd < 0)
    {
      log_error ("cannot bind BIER UDP socket: %s", strerror (errno));
      bier_domain_free (domain);
      return 1;
    }

  listeners[n_listeners].fd = bier_fd;
  listeners[n_listeners].kind = LISTEN_BIER;
  listeners[n_listeners].imp = NULL;
  n_listeners++;

  for (imp = domain->imps; imp; imp = imp->next)
    {
      int fd;

      if (n_listeners >= MAX_LISTENERS - 1)
        {
          log_error ("too many imposition listeners");
          close (bier_fd);
          bier_domain_free (domain);
          return 1;
        }

      fd = udp_socket (imp->listen_addr, imp->listen_port);
      if (fd < 0)
        {
          log_error ("cannot bind imposition %u on port %u: %s", imp->id,
                     imp->listen_port, strerror (errno));
          for (size_t i = 0; i < n_listeners; i++)
            close (listeners[i].fd);
          bier_domain_free (domain);
          return 1;
        }

      listeners[n_listeners].fd = fd;
      listeners[n_listeners].kind = LISTEN_IMPOSITION;
      listeners[n_listeners].imp = imp;
      n_listeners++;
      log_info ("imposition %u listening on port %u", imp->id,
                imp->listen_port);
    }

  rxbuf = malloc (RX_BUFSIZE);
  if (!rxbuf)
    {
      log_error ("out of memory");
      for (size_t i = 0; i < n_listeners; i++)
        close (listeners[i].fd);
      bier_domain_free (domain);
      return 1;
    }

  ectx.fd = bier_fd;
  log_info ("BIER UDP listener started on port %u", domain->listen_port);

  while (g_running)
    {
      struct pollfd pfds[MAX_LISTENERS + 1];
      size_t nfds = 0;
      int pr;
      size_t i;

      for (i = 0; i < n_listeners; i++)
        {
          pfds[nfds].fd = listeners[i].fd;
          pfds[nfds].events = POLLIN;
          pfds[nfds].revents = 0;
          nfds++;
        }
      if (stdin_open)
        {
          pfds[nfds].fd = STDIN_FILENO;
          pfds[nfds].events = POLLIN;
          pfds[nfds].revents = 0;
          nfds++;
        }

      pr = poll (pfds, nfds, 1000);
      if (pr < 0)
        {
          if (errno == EINTR)
            continue;
          log_error ("poll: %s", strerror (errno));
          break;
        }
      if (pr == 0)
        continue;

      for (i = 0; i < n_listeners; i++)
        {
          ssize_t n;

          if (!(pfds[i].revents & POLLIN))
            continue;

          n = recvfrom (listeners[i].fd, rxbuf, RX_BUFSIZE, 0, NULL, NULL);
          if (n <= 0)
            continue;

          if (listeners[i].kind == LISTEN_BIER)
            bier_forward (domain, rxbuf, (size_t) n, udp_emit, &ectx);
          else
            bier_impose (domain, listeners[i].imp, rxbuf, (size_t) n,
                         udp_emit, &ectx);
        }

      if (stdin_open && (pfds[nfds - 1].revents & (POLLIN | POLLHUP)))
        {
          char *line = NULL;
          size_t cap = 0;
          ssize_t n = getline (&line, &cap, stdin);

          if (n < 0)
            {
              free (line);
              stdin_open = 0;
            }
          else
            {
              process_cli (line, domain);
              free (line);
            }
        }
    }

  log_info ("shutting down");
  free (rxbuf);
  for (size_t i = 0; i < n_listeners; i++)
    close (listeners[i].fd);
  bier_domain_free (domain);
  return 0;
}
