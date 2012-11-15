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

dnl pacemaker > 1.1.8
PKG_CHECK_MODULES(pacemaker, [pacemaker, pacemaker-cib], HAVE_pacemaker=1, HAVE_pacemaker=0)

dnl pacemaker <= 1.1.8
PKG_CHECK_MODULES(pcmk, [pcmk, pcmk-cib], HAVE_pcmk=1, HAVE_pcmk=0)

if test $HAVE_pacemaker = 0 -a $HAVE_pcmk = 0; then
    AC_MSG_ERROR(No package 'pacemaker' found)
elif test $HAVE_pacemaker = 1; then
    CFLAGS="$CFLAGS $glib_CFLAGS $pacemaker_CFLAGS"
else
    dnl Deal with the wrong 'includedir' in pcmk.pc from pacemaker < 1.1.8
    pcmk_CFLAGS="-I${prefix}/include/pacemaker -I${prefix}/include/heartbeat"
    CFLAGS="$CFLAGS $glib_CFLAGS $pcmk_CFLAGS"
fi

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

dnl pacemaker < 1.1.8
AC_CHECK_HEADERS(pacemaker/crm/cluster/stack.h)

dnl pacemaker < 1.1.8
AC_CHECK_HEADERS(pacemaker/crm/common/cluster.h)

dnl pacemaker >= 1.1.8
AC_CHECK_HEADERS(pacemaker/crm/cluster.h)

dnl pacemaker >= 1.1.8
AC_CHECK_LIB(crmcommon, pcmk_strerror)
if test $ac_cv_lib_crmcommon_pcmk_strerror = yes; then
   AC_DEFINE_UNQUOTED(HAVE_PCMK_STRERROR, 1, pacemaker has pcmk_strerror)
fi

dnl pacemaker >= 1.1.8
AC_CHECK_LIB(cib, cib_apply_patch_event)
if test $ac_cv_lib_cib_cib_apply_patch_event = yes; then
   AC_DEFINE_UNQUOTED(HAVE_CIB_APPLY_PATCH_EVENT, 1, pacemaker has cib_apply_patch_event)
fi

dnl pacemaker < 1.1.8
AC_CHECK_LIB(crmcluster, init_ais_connection_once)
if test $ac_cv_lib_crmcluster_init_ais_connection_once = yes; then
   AC_DEFINE_UNQUOTED(HAVE_INIT_AIS_CONNECTION_ONCE, 1, pacemaker has init_ais_connection_once)
fi

AC_PATH_PROGS(POD2MAN, pod2man, pod2man)

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES([Makefile src/Makefile agent/Makefile man/Makefile])

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()
