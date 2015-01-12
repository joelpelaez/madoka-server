/*
 *   module.h - Module header for Madoka NAT Jumper
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

#if !defined (_HELPER_H_)
# define _HELPER_H_

# define MODE_SINGLE	0
# define MODE_THREADED	1
# define MODE_FORKED	2

# if defined (__cplusplus)
#  define EXTERN extern "C"
# else
#  define EXTERN extern
# endif

/* Server information */
struct server
{
  short port_num;		/* In system endian */
  short alter_port;		/* If port fail */
  void *data;			/* Unused */
};

/* Common client address struct */
struct client_addr
{
  unsigned int protocol;	/* protocol number */
  char data[28];		/* Shadow data, depends of protocol */
};

/* Base types for module functions */
typedef int (*init_func) (struct server * server);
typedef void (*exit_func) (void);
typedef int (*worker_func) (int);

/* Thread table */
struct thread_table_t
{
  pthread_t *thread;		/* Pthread ID */
  int mode;			/* Thread state */
  struct thread_table_t *next;	/* Next entry */
};

/* Protocol module */
struct protocol_module
{
  char *name;			/* protocol name */
  init_func init;		/* init function */
  exit_func exit;		/* exit function */
  worker_func worker;           /* worker function */
  int fd;			/* File descriptor to select */
  struct thread_table_t *threads;	/* Threads working */
  unsigned int is_loaded;	/* 1 if load, 0 if not */
};

#endif
