# Default flags

AM_CPPFLAGS = $(LTDLINCL)
AM_CFLAGS = -Wall -I$(top_builddir)/modules -I$(top_srcdir)/include -DMADOKA_MODULE_DIR="\"$(moduledir)\""
AM_LDFLAGS =

bin_PROGRAMS = madoka-server
madoka_server_SOURCES = main.c
madoka_server_CFLAGS = $(AM_CFLAGS) $(GNUTLS_CFLAGS) $(PTHREAD_CFLAGS)
madoka_server_LDFLAGS = $(AM_LDFLAGS) $(GNUTLS_LIBS) $(PTHREAD_LDFLAGS)
madoka_server_LDADD = $(LIBLTDL)
madoka_server_DEPENDENCIES = $(LTDLDEPS)
