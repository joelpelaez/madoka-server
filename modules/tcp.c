/*
 *   tcp.c - TCP Info Module for Madoka NAT Jumper
 *   Copyright (C) 2014  Joel Peláez Jorge
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if defined (HAVE_CONFIG_H)
# include "config.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>
#if defined (HAVE_GNUTLS)
# include <gnutls/gnutls.h>
#endif

#include "helper.h"

#define DH_BITS 2048
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE DATADIR"/crl.pem"
#define CERTFILE DATADIR"/cert.pem"
#define KEYFILE DATADIR"/key.pem"

struct client_tcp_addr
{
  unsigned int protocol;
  unsigned long ipaddr;		/* Send in network order */
  unsigned short port;		/* Send in network order */
};

static int fd_global = -1;

#if defined (HAVE_GNUTLS)
gnutls_certificate_credentials_t x509_cred;
gnutls_priority_t priority_cache;

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  gnutls_priority_set (session, priority_cache);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

  return session;
}

static gnutls_dh_params_t dh_params;

static int
generate_dh_params (void)
{
  int ret;

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  ret = gnutls_dh_params_init (&dh_params);

  if (ret)
    {
      syslog (LOG_ERR, "tcp-module: Error in gnutls_dh_params_init(): %s",
	      gnutls_strerror (ret));
      return -1;
    }

  ret = gnutls_dh_params_generate2 (dh_params, DH_BITS);

  if (ret)
    {
      syslog (LOG_ERR,
	      "tcp-module: Error in gnutls_dh_params_generate2(): %s",
	      gnutls_strerror (ret));
      return -1;
    }

  return 0;
}

static int
tls_init (void)
{
  int ret;

  /* Load default certificates for TLS connection. */

  ret = gnutls_certificate_allocate_credentials (&x509_cred);

  if (ret)
    {
      syslog (LOG_ERR,
	      "tcp-module: Error in gnutls_certificate_allocate_credentials(): %s",
	      gnutls_strerror (ret));
      gnutls_certificate_free_credentials (x509_cred);
      return -1;
    }

  ret = gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE,
						GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      syslog (LOG_ERR,
	      "tcp-module: Error in gnutls_certificate_set_x509_trust_file(): %s",
	      gnutls_strerror (ret));
      gnutls_certificate_free_credentials (x509_cred);
      return -1;
    }

  ret = gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE,
					      GNUTLS_X509_FMT_PEM);

  if (ret < 0)
    {
      syslog (LOG_ERR,
	      "tcp-module: Error in gnutls_certificate_set_x509_crl_file(): %s",
	      gnutls_strerror (ret));
      gnutls_certificate_free_credentials (x509_cred);
      return -1;
    }

  ret = gnutls_certificate_set_x509_key_file (x509_cred, CERTFILE, KEYFILE,
					      GNUTLS_X509_FMT_PEM);

  if (ret < 0)
    {
      syslog (LOG_ERR,
	      "tcp-module: Error in gnutls_certificate_set_x509_key_file(): %s",
	      gnutls_strerror (ret));
      gnutls_certificate_free_credentials (x509_cred);
      return -1;
    }

  ret = gnutls_priority_init (&priority_cache, "NORMAL", NULL);

  if (ret)
    {
      syslog (LOG_ERR, "tcp-module: Error in gnutls_priority_init(): %s",
	      gnutls_strerror (ret));
      gnutls_certificate_free_credentials (x509_cred);
      return -1;
    }

  ret = generate_dh_params ();

  if (ret)
    return -1;

  gnutls_certificate_set_dh_params (x509_cred, dh_params);

  return 0;
}

static void
tls_destroy (void)
{
  gnutls_certificate_free_credentials (x509_cred);
  gnutls_priority_deinit (priority_cache);
}

static void
tls_connection (int fd, struct sockaddr_in client_addr)
{
  int ret = 0;
  char buf[256], cbuf[64], strerr[64];
  struct client_tcp_addr client;
  gnutls_session_t session;

  memset (buf, 0, sizeof (buf));
  memset (cbuf, 0, sizeof (cbuf));
  memset (strerr, 0, sizeof (strerr));
  session = initialize_tls_session ();

  gnutls_transport_set_int (session, fd);

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      syslog (LOG_WARNING, "tcp-module: Error in gnutls_handshake(): %s",
	      gnutls_strerror (ret));
      close (fd);
      gnutls_deinit (session);
      return;
    }

  ret = gnutls_record_recv (session, buf, sizeof (buf));

  if (ret == 0)
    {
      syslog (LOG_WARNING, "tcp-module: Warning: connection closed");
      shutdown (fd, SHUT_RDWR); /* Close properly */
      close (fd);
      gnutls_deinit (session);
      return;
    }

  else if (ret < 0)
    {
      syslog (LOG_WARNING, "tcp-module: Error in gnutls_record_recv(): %s",
	      gnutls_strerror (ret));
      shutdown (fd, SHUT_RDWR); /* Close properly */
      close (fd);
      gnutls_deinit (session);
      return;
    }

  /* Check use madoka protocol */
  if (ret < 6 || strncmp ("MADOKA", buf, 6))
    {
      /* Fail */
      strcpy (buf, "MADOKA PROTOCOL ERROR\n");
      gnutls_record_send (session, buf, strlen (buf));
      gnutls_bye (session, GNUTLS_SHUT_WR);
      gnutls_deinit (session);
      shutdown (fd, SHUT_RDWR);	/* Close properly */
      close (fd);
      return;
    }

  /* Prepare binary and text mode */
  /* Send public ip and port */
  client.protocol = 6;		/* Protocol number */
  client.ipaddr = client_addr.sin_addr.s_addr;
  client.port = client_addr.sin_port;

  sprintf (cbuf, "TCP %s %d\n", inet_ntoa (client_addr.sin_addr),
	   ntohs (client_addr.sin_port));

  if (ret >= 13 && !strncmp ("BINARY", buf + 7, 6))
    ret = gnutls_record_send (session, &client, sizeof (client));

  else				/* Normal (text) mode */
    ret = gnutls_record_send (session, cbuf, strlen (cbuf));

  if (ret < 0)
    {
      syslog (LOG_WARNING, "tcp-module: Error in gnutls_record_send(): %s",
	      strerr);
      shutdown (fd, SHUT_RDWR);	/* Close properly */
      close (fd);
      gnutls_deinit (session);
      return;
    }

  gnutls_bye (session, GNUTLS_SHUT_WR);
  gnutls_deinit (session);
  shutdown (fd, SHUT_RDWR);
  close (fd);
}
#endif

static void *
work_thread (void *args)
{
  int ret, newfd = *(int *) args;
  char buf[256], cbuf[128], strerr[64];
  struct sockaddr_in client_addr;
  socklen_t addr_size = sizeof (client_addr);
  struct client_tcp_addr client;

  memset (buf, 0, sizeof (buf));
  memset (cbuf, 0, sizeof (cbuf));
  memset (&client_addr, 0, sizeof (client_addr));
  memset (&client, 0, sizeof (client));

  ret = getpeername (newfd, (struct sockaddr *) &client_addr, &addr_size);

  if (ret < 0)
    {
      strerror_r (errno, strerr, sizeof (strerr));
      syslog (LOG_WARNING, "tcp-module: Error in getpeername(): %s", strerr);
      close (newfd);
      return NULL;
    }

#if defined (HAVE_GNUTLS) && defined (DIRECT_TLS)
  /* Direct call to GnuTLS */
  tls_connection (newfd, client_addr);
#else

  ret = recv (newfd, buf, sizeof (buf), 0);

  if (ret < 0)
    {
      strerror_r (errno, strerr, sizeof (strerr));
      syslog (LOG_WARNING, "tcp-module: Error in recv(): %s", strerr);
      close (newfd);
      return NULL;
    }

# if defined (HAVE_GNUTLS)
  /* If receive STARTTLS, start TLS connection */
  if (!strncmp ("STARTTLS", buf, 8))
    {
      strcpy (buf, "Ready for StartTLS\n");
      send (newfd, buf, strlen (buf), 0);
      tls_connection (newfd, client_addr);
      return NULL;
    }
# endif

  /* Check use madoka protocol */
  if (ret < 6 || strncmp ("MADOKA", buf, 6))
    {
      /* Fail */
      strcpy (buf, "MADOKA PROTOCOL ERROR\n");
      send (newfd, buf, strlen (buf), 0);
      shutdown (newfd, SHUT_RDWR);	/* Close properly */
      close (newfd);
      return NULL;
    }

  /* Prepare binary and text mode */
  /* Send public ip and port */
  client.protocol = 6;		/* Protocol number */
  client.ipaddr = client_addr.sin_addr.s_addr;
  client.port = client_addr.sin_port;

  sprintf (cbuf, "TCP %s %d\n", inet_ntoa (client_addr.sin_addr),
	   ntohs (client_addr.sin_port));

  if (ret >= 13 && !strncmp ("BINARY", buf + 7, 6))
    ret = send (newfd, &client, sizeof (client), 0);

  else				/* Normal (text) mode */
    ret = send (newfd, cbuf, strlen (cbuf), 0);

  if (ret < 0)
    {
      strerror_r (errno, strerr, sizeof (strerr));
      syslog (LOG_WARNING, "tcp-module: Error in send(): %s", strerr);
      shutdown (newfd, SHUT_RDWR);	/* Close properly */
      close (newfd);
      return NULL;
    }

  shutdown (newfd, SHUT_RDWR);	/* Close properly */
  close (newfd);
#endif
  return NULL;
}

static int
tcp_init (struct server *server_info)
{
  int fd;			/* TCP Socket */
  int ret = 0;
  int yes = 1, flags = 0;
  char buf[256];		/* Error buffer */
  struct sockaddr_in tcp_addr;
  socklen_t addr_size = sizeof (tcp_addr);

  fd_global = -1;		/* Define global file descriptor */
  memset (buf, 0, sizeof (buf));
  memset (&tcp_addr, 0, sizeof (tcp_addr));

  fd = socket (AF_INET, SOCK_STREAM, 0);

  if (fd < 0)
    {
      syslog (LOG_ERR, "tcp-module: Error in socket(): %s", strerror (errno));
      return -1;
    }

  flags = fcntl (fd, F_GETFL);

  if (flags == -1)
    {
      syslog (LOG_ERR, "tcp-module: Error in fcntl(F_GETFL): %s",
	      strerror (errno));
      close (fd);
      return -1;
    }

  ret = fcntl (fd, F_SETFL, flags | O_NONBLOCK);

  if (ret)
    {
      syslog (LOG_ERR, "tcp-module: Error in fcntl(F_SETFL): %s",
	      strerror (errno));
      close (fd);
      return -1;
    }

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int)) == -1)
    {
      syslog (LOG_ERR, "tcp-module: Error in setsockopt(): %s",
	      strerror (errno));
      close (fd);
      return -1;
    }

  tcp_addr.sin_family = AF_INET;
  tcp_addr.sin_addr.s_addr = INADDR_ANY;
  tcp_addr.sin_port = htons (server_info->port_num);

  ret = bind (fd, (struct sockaddr *) &tcp_addr, addr_size);

  if (ret < 0)
    {
      syslog (LOG_ERR, "tcp-module: Error in bind(): %s", strerror (errno));
      close (fd);
      return -1;
    }

  ret = listen (fd, 10);

  if (ret < 0)
    {
      syslog (LOG_ERR, "tcp-module: Error in listen(): %s", strerror (errno));
      close (fd);
      return -1;
    }

#if defined (HAVE_GNUTLS)
  ret = tls_init ();

  if (ret)
    {
      syslog (LOG_ERR, "tcp-module: Error on GnuTLS init");
      close (fd);
      return -1;
    }
#endif

  /* If fd is set, copy to global scope */
  fd_global = fd;

  return fd;
}

static void
tcp_exit (void)
{
  if (fd_global < 0)
    return;

#if defined (HAVE_GNUTLS)
  tls_destroy ();
#endif
  shutdown (fd_global, SHUT_RDWR);
  close (fd_global);
}


static int
tcp_worker (int fd)
{
  static int newfd = -1;
  int ret;
  struct sockaddr_in client_addr;
  socklen_t addr_size;
  pthread_t thread;
  /* Prepare new thread */

  newfd = accept (fd, (struct sockaddr *) &client_addr, &addr_size);

  if (newfd < 0)
    {
      syslog (LOG_ERR, "tcp-module: Error in accept(): %s", strerror (errno));
      return -1;
    }

  ret = pthread_create (&thread, NULL, work_thread, &newfd);

  if (ret)
    {
      syslog (LOG_ERR, "tcp-module: Error in pthread_create(): %s",
	      strerror (ret));
      close (fd);
      return -1;
    }

  pthread_detach (thread);

  return 0;
}

struct protocol_module tcp_module = {
  .name = "tcp",
  .init = tcp_init,
  .exit = tcp_exit,
  .worker = tcp_worker,
  .fd = -1,
  .threads = NULL,
  .is_loaded = 0,		/* set by main server thread */
};

struct protocol_module *
module_init (void)
{
  return &tcp_module;
}
