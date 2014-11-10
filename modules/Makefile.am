# Default flags

AM_CPPFLAGS = $(LTDLINCL)
AM_CFLAGS = -Wall -I$(top_srcdir)/include
AM_LDFLAGS =

module_LTLIBRARIES = tcp-module.la

tcp_module_la_SOURCES = tcp.c
tcp_module_la_CFLAGS = ${AM_CFLAGS} ${PTHREAD_CFLAGS}
tcp_module_la_LDFLAGS = -no-undefined -module -avoid-version \
			${AM_LDFLAGS} ${PTHREAD_LDFLAGS}

noinst_HEADERS = modules.h
CLEANFILES = $(noinst_HEADERS)

modules.h:	$(top_builddir)/scripts/gen_module_list
	$< < $(srcdir)/modules.list > $@
