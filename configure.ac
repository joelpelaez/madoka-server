#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([madoka], [0.1], [joelpelaez@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

# Checks for libraries.

# Check libltdl
LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen win32-dll])
LTDL_INIT
LT_LIB_DLLOAD

# Check pthread library
AX_PTHREAD

# Add custom dir
AC_SUBST([moduledir], ['$(libdir)/madoka/modules'])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h stdint.h stdlib.h string.h sys/types.h sys/socket.h sys/stat.h syslog.h unistd.h], ,[
		AC_MSG_ERROR(You need a POSIX compliant system to compile madoka)])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([memset socket strerror strtol], ,[
		AC_MSG_ERROR(You need a POSIX compliant system to compile madoka)])

# configure options
AC_DEFINE([MADOKA_LOG_NAME], ["madoka"],
	[Define custom syslog indenity name])

AC_ARG_WITH([custom-log-name],
	AS_HELP_STRING([--with-custom-log-name=LOGNAME],
	[define custom syslog identity name]))

AS_IF([test "x$with_custom_log_name" != "xno" && test "x$with_custom_log_name" != "x"],
	[
	AS_IF([test "x$with_custom_log_name" == "xyes"],
        	[
		AC_MSG_WARN([--with-custom-log-name argument undefined: using default logging name])
		 with_custom_log_name="madoka"
		])
	AC_DEFINE_UNQUOTED([MADOKA_LOG_NAME], ["$with_custom_log_name"])])


AC_CONFIG_FILES([Makefile scripts/Makefile modules/Makefile src/Makefile])

AC_OUTPUT
