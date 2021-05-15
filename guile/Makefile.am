guilehomedir = $(datadir)/guile/site/3.0

guilehome_DATA = gssapi.scm

gssapi.scm: gssapi.scm.src
	$(SED) -e 's|LIBGUILE_GSSAPI_SO_PLACEHOLDER|$(libdir)/libguile-gssapi.so|g' $^ >$@
