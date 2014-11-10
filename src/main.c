/*
 *   server.c - Madoka NAT Jumper - Server
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

#if defined (_POSIX_C_SOURCE)
# define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ltdl.h>

#include "helper.h"
#include "modules.h"		/* Usable modules */

#if defined (HAVE_CONFIG_H)
# include "config.h"		/* autoconf values */
#else
# include "default.h"		/* default values */
#endif

static int run_server;
struct protocol_module **modules;

static void
quit_server (int mode, int code)
{
  int i;

  run_server = 0;

  for (i = 0; i < modules_list_num; i++)
    {
      if (modules[i] && modules[i]->is_loaded)
	modules[i]->exit ();
    }

  lt_dlexit ();

  syslog (LOG_NOTICE, "Terminate server with exit code: %d", code);

  exit (code);
}

static void
handler (int sig, siginfo_t *si, void *unused)
{
  syslog (LOG_NOTICE, "Terminate server with signal: %d", sig);

  quit_server (0, 0);
}

static void
skeleton_daemon ()
{
  pid_t pid;
  struct sigaction sa;

  sa.sa_flags = SA_SIGINFO;
  sigemptyset (&sa.sa_mask);
  sa.sa_sigaction = handler;

  /* Fork off the parent process */
  pid = fork ();

  /* An error occurred */
  if (pid < 0)
    {
      syslog (LOG_ERR, "Error while forking process: %s", strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Success: Let the parent terminate */
  if (pid > 0)
    {
      exit (EXIT_SUCCESS);
    }

  /* On success: The child process becomes session leader */
  if (setsid () < 0)
    {
      syslog (LOG_ERR, "Error while setting new session id: %s",
	      strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Catch, ignore and handle signals */
  if (sigaction (SIGUSR1, &sa, NULL))
    {
      syslog (LOG_ERR, "Error while setting signal handler: %s",
	      strerror (errno));
      exit (EXIT_FAILURE);
    }
  signal (SIGHUP, SIG_IGN);

  /* Set new file permissions */
  umask (0);

  /* Change the working directory to the root directory */
  /* or another appropriated directory */
  if (chdir ("/"))
    {
      syslog (LOG_ERR, "Error while changing working directory: %s",
	      strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Close out the standard file descriptors */
  close (STDIN_FILENO);
  close (STDOUT_FILENO);
  close (STDERR_FILENO);
}

int
main (int argc, char **argv)
{
  int i = 0;
  int ret = 0;
  char buf[256];
  struct server server_info;
  struct protocol_module *(*load_func) (void) = NULL;
  lt_dlhandle module = NULL;

  memset (buf, 0, sizeof (buf));

  if (argc != 3)
    {
      fprintf (stderr, "Bad arguments: use madoka-server <ipaddr> <port>\n");
      exit (EXIT_FAILURE);
    }

  server_info.port_num = strtol (argv[2], NULL, 10);

  if (errno)
    {
      perror ("Bad port value");
      exit (EXIT_FAILURE);
    }

  /* Prepare server */
  openlog (MADOKA_LOG_NAME, LOG_PID, LOG_DAEMON);
  skeleton_daemon ();
  syslog (LOG_NOTICE, "Start madoka-server with ip and port: %s:%d", argv[1],
	  server_info.port_num);

  /* Check module list and alloc memory for this. */
  modules = malloc (sizeof (*modules) * modules_list_num);
  memset (modules, 0, sizeof (*modules) * modules_list_num);

  if (!modules)
    {
      syslog (LOG_ERR, "Error in malloc(): %s", strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Prepare all modules to load */

  lt_dlinit ();

  for (i = 0; i < modules_list_num; i++)
    {

      /* Put module filename */
      strcpy (buf, MADOKA_MODULE_DIR);
      strcat (buf, "/");
      strcat (buf, modules_list_name[i]);
      strcat (buf, LT_MODULE_EXT);

      module = lt_dlopen (buf);

      if (!module)
	{
	  syslog (LOG_WARNING,
		  "Error while loading module in lt_dlopen(): %s\n",
		  lt_dlerror ());
	  continue;		/* Check next module */
	}

      load_func = lt_dlsym (module, "module_init");

      if (!load_func)
	{
	  syslog (LOG_WARNING,
		  "Error while loading module function in lt_dlsym(): %s\n",
		  lt_dlerror ());
	  continue;		/* Check next module */
	}

      modules[i] = load_func ();

      if (!modules[i])
	{
	  syslog (LOG_WARNING,
		  "Error while executing module preinit function");
	  continue;		/* Check next module */
	}

      ret = modules[i]->init (&server_info);

      if (ret)
	{
	  syslog (LOG_WARNING, "Error while executing module init function");
	  modules[i]->is_loaded = 0;
	  continue;		/* Invalid module and check next */
	}

      modules[i]->is_loaded = 1;
      syslog (LOG_NOTICE, "Module %s loaded successfully",
	      modules_list_name[i]);

      /* Set run_server if some module is loaded successfully */
      run_server = 1;
    }

  while (run_server)
    {
      /* TODO: Use better wait method */
      sleep (10);
    }

  /* If we can't run server, exit it with code 1 */
  quit_server (0, 1);

  return 0;
}
