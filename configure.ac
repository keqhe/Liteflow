#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([flowvisor], [0.4], [rob.sherwood@stanford.edu])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])


AC_DEFUN([OPENFLOWSRC_DEFAULT],[`pwd`/../openflow])


dnl Give option to change location of openflow directory
AC_ARG_WITH(openflow-src-dir,
        [  --with-openflow-src-dir=PATH    Specify path to OpenFlow Source Directory (default: OPENFLOWSRC_DEFAULT) ],
	[ 
		case "$withval" in
			# Relative paths
			./*|../*)       withval="`pwd`/$withval"
		esac
		if test "x$withval" = "x" ; then
			AC_MSG_ERROR([--with-openflow-src-dir needs an argument],[1])
		fi
		OPENFLOWSRC=$withval
	 ],
	[OPENFLOWSRC=OPENFLOWSRC_DEFAULT]
)

dnl Make sure we have the openflow source somewhere
AC_CHECK_FILE(
	[$OPENFLOWSRC/include/openflow/openflow.h],
	[],
	[AC_MSG_ERROR(
		[Could not find openflow source at $OPENFLOWSRC -- please install]
		,[1])
	])

dnl Define $(openflowsrc) in makefile
AC_SUBST([openflowsrc],$OPENFLOWSRC)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_RANLIB


# LAME with extra lame sauce
#	couldn't convince autoreconf to source m4/large_file.m4 
#	despite "-I m4"
#	put here explicitly as a work around
AC_DEFUN([LARGE_FILES],[
	LARGEFILES_CFLAGS="-D_LARGEFILE_SOURCE `getconf LFS_CFLAGS` "
	LARGEFILES_LDFLAGS="`getconf LFS_LDFLAGS` `getconf LFS_LIBS` "
	AC_SUBST([LARGEFILES_CFLAGS],$LARGEFILES_CFLAGS)
	AC_SUBST([LARGEFILES_LDFLAGS],$LARGEFILES_LDFLAGS)
])

# custom; large file support
LARGE_FILES
# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([config.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([strerror])


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
