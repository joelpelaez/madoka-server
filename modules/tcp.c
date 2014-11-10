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


#ifdef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <errno.h>
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

#include "helper.h"

struct client_tcp_addr
{
  unsigned int protocol;
  unsigned long ipaddr;		/* Send in network order */
  unsigned short port;		/* Send in network order */
};

struct thread_info
{
  int fd;
};

static pthread_t thread;

static int fd_global = -1;

static volatile int run_thread;	/* Thread control variable */

static void *
work_thread (void *args)
{
  int ret, newfd;
  char buf[256], cbuf[128], strerr[64];
  struct thread_info *info = (struct thread_info *) args;
  struct sockaddr_in client_addr;
  socklen_t addr_size = sizeof (client_addr);
  struct client_tcp_addr client;

  while (run_thread)		/* If can run */
    {
      memset (buf, 0, sizeof (buf));
      memset (cbuf, 0, sizeof (cbuf));
      memset (&client_addr, 0, sizeof (client_addr));
      memset (&client, 0, sizeof (client));

      newfd = accept (info->fd, (struct sockaddr *) &client_addr, &addr_size);

      if (newfd < 0)
	{
	  strerror_r (errno, strerr, sizeof (strerr));
	  syslog (LOG_ERR, "tcp-module: Error in accept(): %s\n", strerr);
	  close (info->fd);
	  pthread_exit (NULL);
	}

      ret = recv (newfd, buf, sizeof (buf), 0);

      if (ret < 0)
	{
	  strerror_r (errno, strerr, sizeof (strerr));
	  syslog (LOG_WARNING, "tcp-module: Error in recv(): %s\n", strerr);
	  close (newfd);
	  continue;
	}

      /* Check use madoka protocol */
      if (ret < 6 || strncmp ("MADOKA", buf, 6))
	{
	  /* Fail */
	  strcpy (buf, "MADOKA PROTOCOL ERROR\n");
	  send (newfd, buf, strlen (buf), 0);
	  shutdown (newfd, SHUT_RDWR);	/* Close properly */
	  close (newfd);
	  continue;
	}

      /* Prepare binary and text mode */
      /* Send public ip and port */
      client.protocol = 6;	/* Protocol number */
      client.ipaddr = client_addr.sin_addr.s_addr;
      client.port = client_addr.sin_port;

      sprintf (cbuf, "TCP %s %d\n", inet_ntoa (client_addr.sin_addr),
	       ntohs (client_addr.sin_port));

      if (ret >= 13 && !strncmp ("BINARY", buf + 7, 6))
	ret = send (newfd, &client, sizeof (client), 0);

      else			/* Normal (text) mode */
	ret = send (newfd, cbuf, strlen (cbuf), 0);

      if (ret < 0)
	{
	  strerror_r (errno, strerr, sizeof (strerr));
	  syslog (LOG_WARNING, "Error in send(): %s\n", strerr);
	  shutdown (newfd, SHUT_RDWR);	/* Close properly */
	  close (newfd);
	  continue;
	}

      shutdown (newfd, SHUT_RDWR);	/* Close properly */
      close (newfd);
    }

  return NULL;
}

static int
tcp_init (struct server *server_info)
{
  int fd;			/* TCP Socket */
  int ret = 0;
  int yes = 1;
  char buf[256];		/* Error buffer */
  struct sockaddr_in tcp_addr;
  socklen_t addr_size = sizeof (tcp_addr);
  struct thread_info *args;

  fd_global = -1;		/* Define global file descriptor */
  memset (buf, 0, sizeof (buf));
  memset (&tcp_addr, 0, sizeof (tcp_addr));
  args = malloc (sizeof (*args));
  memset (args, 0, sizeof (*args));

  fd = socket (AF_INET, SOCK_STREAM, 0);

  if (fd < 0)
    {
      syslog (LOG_ERR, "Error in socket(): %s\n", strerror (errno));
      return -1;
    }

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int)) == -1)
    {
      syslog (LOG_ERR, "Error in setsockopt(): %s\n", strerror (errno));
      return -1;
    }

  tcp_addr.sin_family = AF_INET;
  tcp_addr.sin_addr.s_addr = INADDR_ANY;
  tcp_addr.sin_port = htons (server_info->port_num);

  ret = bind (fd, (struct sockaddr *) &tcp_addr, addr_size);

  if (ret < 0)
    {
      syslog (LOG_ERR, "Error in bind(): %s\n", strerror (errno));
      close (fd);
      return -1;
    }

  ret = listen (fd, 10);

  if (ret < 0)
    {
      syslog (LOG_ERR, "Error in listen(): %s\n", strerror (errno));
      close (fd);
      return -1;
    }

  args->fd = fd;

  ret = pthread_create (&thread, NULL, work_thread, args);

  if (ret)
    {
      syslog (LOG_ERR, "Error in pthread_create(): %s\n", strerror (ret));
      close (fd);
      return -1;
    }

  /* If fd is set, copy to global scope */
  fd_global = fd;
  run_thread = 1;

  return 0;
}

static void
tcp_exit (void)
{
  if (fd_global < 0 || !run_thread)
    return;

  run_thread = 0;		/* Prepare thread join */
  pthread_cancel (thread);
  pthread_join (thread, NULL);
  shutdown (fd_global, SHUT_RDWR);
  close (fd_global);
}

struct protocol_module tcp_module = {
  .name = "tcp",
  .init = tcp_init,
  .exit = tcp_exit,
  .mode = MODE_THREADED,
  .is_loaded = 0,		/* set by main server thread */
};

struct protocol_module *
module_init (void)
{
  return &tcp_module;
}
