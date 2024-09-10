#
# Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
#

sdma_happy="no"
AC_ARG_WITH([sdma],
            [AS_HELP_STRING([--with-sdma=(DIR)], [Enable the use of SDMA (default is guess).])],
            [], [with_sdma=guess])

AS_IF([test "x$with_sdma" != xno],
    [AS_IF([test "x$with_sdma" = "xguess" -o "x$with_sdma" = "xyes" -o "x$with_sdma" = "x"],
           [ucx_check_sdma_dir=/usr],
           [ucx_check_sdma_dir=$with_sdma])

     AS_IF([test -d "$ucx_check_sdma_dir/lib64"],
           [libsuff="64"],
           [libsuff=""])

      ucx_sdma_include_dir="$ucx_check_sdma_dir/include"
      ucx_sdma_lib_dir="$ucx_check_sdma_dir/lib$libsuff"

      save_LDFLAGS="$LDFLAGS"
      save_CPPFLAGS="$CPPFLAGS"

      CPPFLAGS="-I$ucx_sdma_include_dir $CPPFLAGS"
      LDFLAGS="-L$ucx_sdma_lib_dir $LDFLAGS"

      AC_CHECK_HEADER([$ucx_sdma_include_dir/mdk_sdma.h],
          [
              AS_IF([test -f $ucx_sdma_lib_dir/libsdma_dk.so],
                    [
                     AC_SUBST([SDMA_CPPFLAGS], [-I$ucx_sdma_include_dir])
                     AC_SUBST([SDMA_LDFLAGS], [-L$ucx_sdma_lib_dir])
                     uct_modules="${uct_modules}:sdma"
                     sdma_happy="yes"

                     CPPFLAGS="$save_CPPFLAGS"
                     LDFLAGS="$save_LDFLAGS"

                     AC_MSG_NOTICE([SDMA dependcy library found in $ucx_sdma_lib_dir ])
                    ],
                    [AC_MSG_WARN([SDMA requested but libsdma_dk is not found in $ucx_sdma_lib_dir])]
                   )
            ],
            [AC_MSG_WARN([SDMA requested but required file (mdk_sdma.h) could not be found in $ucx_sdma_include_dir])]
        ) 
      ],
      [AC_MSG_WARN([SDMA not supported])]
    )

AM_CONDITIONAL([HAVE_SDMA], [test "x$sdma_happy" != xno])
AC_CONFIG_FILES([src/uct/sm/scopy/sdma/Makefile])