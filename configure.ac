dnl
dnl autoconf for Agents
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ(2.63)

dnl Suggested structure:
dnl     information on the package
dnl     checks for programs
dnl     checks for libraries
dnl     checks for header files
dnl     checks for types
dnl     checks for structures
dnl     checks for compiler characteristics
dnl     checks for library functions
dnl     checks for system services

AC_INIT([sbd], 
	[1.0],
	[lmb@suse.com])
AC_CANONICAL_HOST
AC_CONFIG_AUX_DIR(.)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

PKG_CHECK_MODULES(glib, [glib-2.0])
PKG_CHECK_MODULES(libcoroipcc, [libcoroipcc])
PKG_CHECK_MODULES(pcmk, [pcmk, pcmk-cib])
PKG_CHECK_MODULES(libxml, [libxml-2.0])

dnl     checks for libraries
AC_CHECK_LIB(aio, io_setup, , missing="yes")
AC_CHECK_LIB(plumbgpl, init_set_proc_title, , missing="yes")
AC_CHECK_LIB(crmcommon, set_crm_log_level, , missing="yes")
AC_CHECK_LIB(cib, cib_new, , missing="yes")
AC_CHECK_LIB(pe_status, pe_find_node, , missing="yes")
AC_CHECK_LIB(pe_rules, test_rule, , missing="yes")
AC_CHECK_LIB(crmcluster, crm_peer_init, , missing="yes")

if test "$missing" = "yes"; then
   AC_MSG_ERROR([Missing required libraries or functions.])
fi




dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES([Makefile src/Makefile agent/Makefile man/Makefile])

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()
