global-incdirs-y += include
srcs-y += bench_ta.c

# BENCH_CFLAGS is passed on the make command line (e.g. -DMITIG for the
# mitigated build).
cflags-y += $(BENCH_CFLAGS)
