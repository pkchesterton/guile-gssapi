lib_LTLIBRARIES = libguile-gssapi.la

C_SOURCES = bindings.c
libguile_gssapi_la_SOURCES = $(C_SOURCES)
libguile_gssapi_la_CFLAGS = @GUILE_CFLAGS@ @GUILE_LIBS@

BUILT_SOURCES = snarfed_includeme.h
snarfed_includeme.h: $(C_SOURCES)
	guile-snarf -o $@ @GUILE_CFLAGS@ $(C_SOURCES)
