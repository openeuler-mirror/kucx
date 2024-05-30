#
# Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
#

sdma_happy="no"
AC_ARG_WITH([sdma],
            [AS_HELP_STRING([--with-sdma=(DIR)], [Enable the use of SDMA (default is /opt/sdma).])],
            [], [with_sdma=/opt/sdma]
            )

AS_IF([test "x$with_sdma" != xno],
    [
        ucx_check_sdma_dir=$with_sdma/include
        ucx_sdma_lib_dir=$with_sdma/lib
            save_LDFLAGS="$LDFLAGS"
        save_CPPFLAGS="$CPPFLAGS"

        CPPFLAGS="-I$ucx_check_sdma_dir $CPPFLAGS"
        LDFLAGS="-L$ucx_sdma_lib_dir $LDFLAGS"

        AC_CHECK_HEADER([$ucx_check_sdma_dir/mdk_sdma.h],
            [
                AS_IF([test -f $ucx_sdma_lib_dir/libsdma.so],
                    [
                    AC_SUBST([SDMA_CPPFLAGS], [-I$ucx_check_sdma_dir])
                    AC_SUBST([SDMA_LDFLAGS], [-L$ucx_sdma_lib_dir])
                    uct_modules="${uct_modules}:sdma"
                    sdma_happy="yes"

                    CPPFLAGS="$save_CPPFLAGS"
                    LDFLAGS="$save_LDFLAGS"

                    AC_MSG_WARN([SDMA dependcy library found in $ucx_sdma_lib_dir ])
                    
                    ],
                    [AC_MSG_WARN([SDMA requested but libsdma is not found in $ucx_sdma_lib_dir])]
                )
            ],
            [AC_MSG_WARN([SDMA requested but required file (mdk_sdma.h) could not be found in $ucx_check_sdma_dir])]
        )
    ],
    [AC_MSG_WARN([SDMA not supported])]
    )

AM_CONDITIONAL([HAVE_SDMA], [test "x$sdma_happy" != xno])
AC_CONFIG_FILES([src/uct/sm/scopy/sdma/Makefile])