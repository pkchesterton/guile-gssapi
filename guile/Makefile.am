guilehomedir = $(datadir)/guile/site/3.0

guilehome_DATA = guile-gssapi.scm

guile-gssapi.scm: guile-gssapi.scm.src
	$(SED) -e 's|LIBGUILE_GSSAPI_SO_PLACEHOLDER|$(libdir)/libguile-gssapi.so|g' $^ >$@
