#
# Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2001-2014. ALL RIGHTS RESERVED.
# Copyright (C) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
# Copyright (C) The University of Tennessee and the University of Tennessee Research Foundation. 2016. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#


AC_ARG_WITH([verbs],
        [AS_HELP_STRING([--with-verbs(=DIR)],
            [Build OpenFabrics support, adding DIR/include, DIR/lib, and DIR/lib64 to the search path for headers and libraries])],
        [],
        [with_verbs=/usr])

AS_IF([test "x$with_verbs" = "xyes"], [with_verbs=/usr])
AS_IF([test -d "$with_verbs"], [with_ib=yes; str="with verbs support from $with_verbs"], [with_ib=no; str="without verbs support"])
AS_IF([test -d "$with_verbs/lib64"],[libsuff="64"],[libsuff=""])

AC_MSG_NOTICE([Compiling $str])

#
# RC Support
#
AC_ARG_WITH([rc],
            [AS_HELP_STRING([--with-rc], [Compile with IB Reliable Connection support])],
            [],
            [with_rc=yes])


#
# UD Support
#
AC_ARG_WITH([ud],
            [AS_HELP_STRING([--with-ud], [Compile with IB Unreliable Datagram support])],
            [],
            [with_ud=yes])


#
# DC Support
#
AC_ARG_WITH([dc],
            [AS_HELP_STRING([--with-dc], [Compile with IB Dynamic Connection support])],
            [],
            [with_dc=yes])


#
# mlx5 DV support
#
AC_ARG_WITH([mlx5-dv],
            [AS_HELP_STRING([--with-mlx5-dv], [Compile with mlx5 Direct Verbs
                support. Direct Verbs (DV) support provides additional
                acceleration capabilities that are not available in a
                regular mode.])])

#
# optimized gid table interface support
#
AC_ARG_WITH([opt-gid-table],
            [AS_HELP_STRING([--with-opt-gid-table], [Compile with optimized gid table interface
                support. ibv_query_gid_table support provides acceleration capabilities
                when ib init.])])

#
# TM (IB Tag Matching) Support
#
AC_ARG_WITH([ib-hw-tm],
            [AS_HELP_STRING([--with-ib-hw-tm], [Compile with IB Tag Matching support])],
            [],
            [with_ib_hw_tm=yes])


#
# DM Support
#
AC_ARG_WITH([dm],
            [AS_HELP_STRING([--with-dm], [Compile with Device Memory support])],
            [],
            [with_dm=yes])

#
# DEVX Support
#
AC_ARG_WITH([devx],
            [AS_HELP_STRING([--with-devx], [Compile with DEVX support])],
            [],
            [with_devx=check])

#
# Check basic IB support: User wanted at least one IB transport, and we found
# verbs header file and library.
#
AS_IF([test "x$with_ib" = "xyes"],
        [
        save_LDFLAGS="$LDFLAGS"
        save_CFLAGS="$CFLAGS"
        save_CPPFLAGS="$CPPFLAGS"
        AS_IF([test "x/usr" = "x$with_verbs"],
          [],
          [verbs_incl="-I$with_verbs/include"
           verbs_libs="-L$with_verbs/lib$libsuff"])
        LDFLAGS="$verbs_libs $LDFLAGS"
        CFLAGS="$verbs_incl $CFLAGS"
        CPPFLAGS="$verbs_incl $CPPFLAGS"
        AC_CHECK_HEADER([infiniband/verbs.h], [],
                        [AC_MSG_WARN([ibverbs header files not found]); with_ib=no])
        AC_CHECK_LIB([ibverbs], [ibv_get_device_list],
            [
            AC_SUBST(IBVERBS_LDFLAGS,  ["$verbs_libs -libverbs"])
            AC_SUBST(IBVERBS_DIR,      ["$with_verbs"])
            AC_SUBST(IBVERBS_CPPFLAGS, ["$verbs_incl"])
            AC_SUBST(IBVERBS_CFLAGS,   ["$verbs_incl"])
            ],
            [AC_MSG_WARN([libibverbs not found]); with_ib=no])

        have_ib_funcs=yes
        LDFLAGS="$LDFLAGS $IBVERBS_LDFLAGS"
        AC_CHECK_DECLS([ibv_wc_status_str,
                        ibv_event_type_str,
                        ibv_query_gid,
                        ibv_get_device_name,
                        ibv_create_srq,
                        ibv_get_async_event],
                       [],
                       [have_ib_funcs=no],
                       [#include <infiniband/verbs.h>])
        AS_IF([test "x$have_ib_funcs" != xyes],
              [AC_MSG_WARN([Some IB verbs are not found. Please make sure OFED version is 1.5 or above.])
               with_ib=no])

        LDFLAGS="$save_LDFLAGS"
        CFLAGS="$save_CFLAGS"
        CPPFLAGS="$save_CPPFLAGS"
        ],[:])

AS_IF([test "x$with_ib" = "xyes"],
      [
       save_LDFLAGS="$LDFLAGS"
       save_CFLAGS="$CFLAGS"
       save_CPPFLAGS="$CPPFLAGS"
       LDFLAGS="$IBVERBS_LDFLAGS $LDFLAGS"
       CFLAGS="$IBVERBS_CFLAGS $CFLAGS"
       CPPFLAGS="$IBVERBS_CPPFLAGS $CPPFLAGS"

       AC_CHECK_DECLS([IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN],
                      [have_cq_io=yes], [], [[#include <infiniband/verbs.h>]])

       AS_IF([test "x$with_mlx5_dv" != xno], [
              AC_MSG_NOTICE([Checking for DV bare-metal support])

              AC_CHECK_LIB([mlx5-rdmav2], [mlx5dv_query_device],
                                    [AC_SUBST(LIB_MLX5, [-lmlx5-rdmav2])],[
              AC_CHECK_LIB([mlx5], [mlx5dv_query_device],
                                    [AC_SUBST(LIB_MLX5, [-lmlx5])],
                                    [with_mlx5_dv=no], [-libverbs])], [-libverbs])

              AS_IF([test "x$with_mlx5_dv" != xno], [
                       AC_CHECK_HEADERS([infiniband/mlx5dv.h],
                               [with_mlx5_dv=yes
                                mlx5_include=mlx5dv.h], [], [ ])])
                       AC_CHECK_DECLS([
                           mlx5dv_init_obj,
                           mlx5dv_create_qp,
                           mlx5dv_is_supported,
                           mlx5dv_devx_subscribe_devx_event], [],
                          [with_mlx5_dv=no],
                          [[#include <infiniband/mlx5dv.h>]])

              AS_IF([test "x$with_mlx5_dv" = "xyes" -a "x$have_cq_io" = "xyes" ], [
                       AC_CHECK_DECLS([
                           MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE,
                           MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE,
                           MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE,
                           MLX5DV_UAR_ALLOC_TYPE_BF,
                           MLX5DV_UAR_ALLOC_TYPE_NC,
                           mlx5dv_devx_umem_reg_ex],
                                  [], [], [[#include <infiniband/mlx5dv.h>]])
                       AC_CHECK_MEMBERS([struct mlx5dv_cq.cq_uar],
                                  [], [], [[#include <infiniband/mlx5dv.h>]])
                       AC_CHECK_DECLS([MLX5DV_OBJ_AH], [has_get_av=yes],
                                      [], [[#include <infiniband/mlx5dv.h>]])
                       AC_CHECK_DECLS([MLX5DV_DCTYPE_DCT],
                                  [have_dc_dv=yes], [], [[#include <infiniband/mlx5dv.h>]])
                       AC_CHECK_DECLS([ibv_alloc_td],
                                  [has_res_domain=yes], [], [[#include <infiniband/verbs.h>]])
                       AS_IF([test x$with_devx != xno], [
                               AC_CHECK_DECL(MLX5DV_CONTEXT_FLAGS_DEVX, [
                                          AC_DEFINE([HAVE_DEVX], [1], [DEVX support])
                                          have_devx=yes
                               ], [], [[#include <infiniband/mlx5dv.h>]])])])])

       AS_IF([test "x$has_res_domain" = "xyes" -a "x$have_cq_io" = "xyes" ], [], [
               with_mlx5_dv=no])

       AS_IF([test "x$with_mlx5_dv" = "xyes"],
             [AC_DEFINE([HAVE_MLX5_DV], 1, [mlx5 DV support])
              AS_IF([test "x$has_get_av" = "xyes"],
                 [AC_DEFINE([HAVE_MLX5_HW_UD], 1, [mlx5 UD bare-metal support])])])

       AS_IF([test x$with_devx = xyes -a x$have_devx != xyes], [
               AC_MSG_ERROR([devx requested but not found])])

       AC_CHECK_DECLS([IBV_LINK_LAYER_INFINIBAND,
                       IBV_LINK_LAYER_ETHERNET,
                       IBV_EVENT_GID_CHANGE,
                       IBV_TRANSPORT_USNIC,
                       IBV_TRANSPORT_USNIC_UDP,
                       IBV_TRANSPORT_UNSPECIFIED,
                       ibv_create_qp_ex,
                       ibv_create_cq_ex,
                       ibv_create_srq_ex,
                       ibv_reg_dmabuf_mr],
                      [], [], [[#include <infiniband/verbs.h>]])

       # Check ECE operation APIs are supported by rdma-core package
       AC_CHECK_DECLS(ibv_set_ece,
                     [], [], [[#include <infiniband/verbs.h>]])

       # We shouldn't confuse upstream ibv_query_device_ex with
       # legacy MOFED one, distinguish by arguments number
       AC_CHECK_DECL(ibv_query_device_ex, [
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <infiniband/verbs.h>]],
                         [[ibv_query_device_ex(NULL, NULL, NULL)]])],
                         [AC_DEFINE([HAVE_DECL_IBV_QUERY_DEVICE_EX], 1,
                            [have upstream ibv_query_device_ex])])],
                            [], [[#include <infiniband/verbs.h>]])

       # We could use ibv_query_gid_table to quickly get gids information
       AS_IF([test "x$with_opt_gid_table" = "xyes" ], [
            AC_CHECK_DECL(ibv_query_gid_table, [
            AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <infiniband/verbs.h>]],
                                [[ibv_query_gid_table(NULL, NULL, NULL, NULL)]])],
                                [AC_DEFINE([HAVE_IBV_QUERY_GID_TABLE], 1,
                                    [use ibv_query_gid_table])])],
                                    [], [[#include <infiniband/verbs.h>]])])

       AC_CHECK_MEMBERS([struct ibv_device_attr_ex.pci_atomic_caps],
                        [], [], [[#include <infiniband/verbs.h>]])

       AC_CHECK_DECLS([IBV_ACCESS_RELAXED_ORDERING,
                       IBV_ACCESS_ON_DEMAND,
                       IBV_QPF_GRH_REQUIRED],
                      [], [], [[#include <infiniband/verbs.h>]])

       AC_CHECK_DECLS(ibv_advise_mr, [with_prefetch=yes], [],
                      [[#include <infiniband/verbs.h>]])

       AS_IF([test "x$with_prefetch" = "xyes" ], [
           AC_DEFINE([HAVE_PREFETCH], 1, [Prefetch support])])

       AC_CHECK_MEMBERS([struct mlx5_wqe_av.base,
                         struct mlx5_grh_av.rmac],
                        [], [], [[#include <infiniband/$mlx5_include>]])

       AC_CHECK_MEMBERS([struct mlx5_cqe64.ib_stride_index],
                        [], [], [[#include <infiniband/$mlx5_include>]])

       AC_DEFINE([HAVE_IB], 1, [IB support])

       AS_IF([test "x$with_dc" != xno -a "x$have_dc_dv" = xyes -a "x$with_mlx5_dv" = "xyes"], [
           AC_DEFINE([HAVE_TL_DC], 1, [DC transport support])
           AS_IF([test -n "$have_dc_dv"],
                 [AC_DEFINE([HAVE_DC_DV], 1, [DC DV support])])],
           [with_dc=no])

       AS_IF([test "x$with_rc" != xno],
           [AC_DEFINE([HAVE_TL_RC], 1, [RC transport support])])

       AS_IF([test "x$with_ud" != xno],
           [AC_DEFINE([HAVE_TL_UD], 1, [UD transport support])])

       # XRQ with Tag Matching support
       AS_IF([test "x$with_ib_hw_tm" != xno], [
            AS_IF([test "x$with_mlx5_dv" = "xyes"], [
                AC_CHECK_MEMBER([struct ibv_tmh.tag], [with_ib_hw_tm=upstream], [],
                                [[#include <infiniband/tm_types.h>]])])])

       AS_IF([test "x$with_ib_hw_tm" = xupstream],
           [AC_DEFINE([IBV_HW_TM], 1, [IB Tag Matching support])
            AC_CHECK_MEMBERS([struct ibv_tm_caps.flags], [], [],
                             [#include <infiniband/verbs.h>])])

       # Device Memory support
       AS_IF([test "x$with_dm" != xno], [
           AC_CHECK_DECLS([ibv_alloc_dm],
               [AC_DEFINE([HAVE_IBV_DM], 1, [Device Memory support])],
               [], [[#include <infiniband/verbs.h>]])])

       mlnx_valg_libdir=$with_verbs/lib${libsuff}/mlnx_ofed/valgrind
       AC_MSG_NOTICE([Checking OFED valgrind libs $mlnx_valg_libdir])

       AS_IF([test -d "$mlnx_valg_libdir"],
               [AC_MSG_NOTICE([Added $mlnx_valg_libdir to valgrind LD_LIBRARY_PATH])
               valgrind_libpath="$mlnx_valg_libdir:$valgrind_libpath"])
       LDFLAGS="$save_LDFLAGS"
       CFLAGS="$save_CFLAGS"
       CPPFLAGS="$save_CPPFLAGS"

       uct_modules="${uct_modules}:ib"
    ],
    [
        with_dc=no
        with_rc=no
        with_ud=no
        with_mlx5_dv=no
    ])

#
# For automake
#
AM_CONDITIONAL([HAVE_IB],      [test "x$with_ib" != xno])
AM_CONDITIONAL([HAVE_TL_RC],   [test "x$with_rc" != xno])
AM_CONDITIONAL([HAVE_TL_DC],   [test "x$with_dc" != xno])
AM_CONDITIONAL([HAVE_DC_DV],   [test -n "$have_dc_dv"])
AM_CONDITIONAL([HAVE_TL_UD],   [test "x$with_ud" != xno])
AM_CONDITIONAL([HAVE_MLX5_DV], [test "x$with_mlx5_dv" = xyes])
AM_CONDITIONAL([HAVE_DEVX],    [test -n "$have_devx"])
AM_CONDITIONAL([HAVE_MLX5_HW_UD], [test "x$with_mlx5_dv" != xno -a "x$has_get_av" != xno])

uct_ib_modules=""
m4_include([src/uct/ib/rdmacm/configure.m4])
AC_DEFINE_UNQUOTED([uct_ib_MODULES], ["${uct_ib_modules}"], [IB loadable modules])
AC_CONFIG_FILES([src/uct/ib/Makefile
                 src/uct/ib/ucx-ib.pc])
