#
# Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
#

if HAVE_SDMA

module_LTLIBRARIES     = libuct_sdma.la
libuct_sdma_la_CFLAGS   = $(BASE_CFLAGS) $(SDMA_CPPFLAGS)
libuct_sdma_la_CPPFLAGS = $(BASE_CPPFLAGS) $(SDMA_CPPFLAGS)
libuct_sdma_la_LIBADD   = $(top_builddir)/src/ucs/libucs.la \
                          $(top_builddir)/src/uct/libuct.la
libuct_sdma_la_LDFLAGS  = $(SDMA_LDFLAGS) $(SEC_LDFLAGS) -lsdma_dk
noinst_HEADERS = \
    sdma_iface.h \
    sdma_ep.h \
    sdma_md.h

libuct_sdma_la_SOURCES = \
    sdma_iface.c \
    sdma_ep.c \
    sdma_md.c

include $(top_srcdir)/config/module.am

endif
