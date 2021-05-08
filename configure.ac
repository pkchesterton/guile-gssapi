AC_INIT([guile-gssapi], [0.1.0], [guile-gssapi@eiere.com])
AM_INIT_AUTOMAKE
LT_INIT

AC_PROG_SED

CFLAGS="-Werror -g"

PKG_CHECK_MODULES([GUILE], [guile-3.0])
LIBS+=" $GUILE_LIBS"
CFLAGS+=" $GUILE_CFLAGS"

PKG_CHECK_MODULES([MIT_KRB5_GSSAPI], [mit-krb5-gssapi])
LIBS+=" $MIT_KRB5_GSSAPI_LIBS"
CFLAGS+=" $MIT_KRB5_GSSAPI_CFLAGS"

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  guile/Makefile
])
AC_OUTPUT
