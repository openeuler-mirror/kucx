/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "sys.h"

#include <ucm/api/ucm.h>
#include <ucm/util/log.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


#define UCM_PROC_SELF_MAPS "/proc/self/maps"


void ucm_parse_proc_self_maps(ucm_proc_maps_cb_t cb, void *arg)
{
    static char  *buffer         = MAP_FAILED;
    static size_t buffer_size    = 2048;
    static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
    ssize_t read_size, offset;
    unsigned long start, end;
    char prot_c[4];
    int prot;
    char *ptr, *newline;
    int maps_fd;
    int ret;

    maps_fd = open(UCM_PROC_SELF_MAPS, O_RDONLY);
    if (maps_fd < 0) {
        ucm_fatal("cannot open %s for reading: %m", UCM_PROC_SELF_MAPS);
    }

    /* read /proc/self/maps fully into the buffer */
    pthread_rwlock_wrlock(&lock);

    if (buffer == MAP_FAILED) {
        buffer = ucm_orig_mmap(NULL, buffer_size, PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (buffer == MAP_FAILED) {
            ucm_fatal("failed to allocate maps buffer(size=%zu): %m", buffer_size);
        }
    }

    offset = 0;
    for (;;) {
        read_size = read(maps_fd, buffer + offset, buffer_size - offset);
        if (read_size < 0) {
            /* error */
            if (errno != EINTR) {
                ucm_fatal("failed to read from %s: %m", UCM_PROC_SELF_MAPS);
            }
        } else if (read_size == buffer_size - offset) {
            /* enlarge buffer */
            buffer = ucm_orig_mremap(buffer, buffer_size, buffer_size * 2,
                                     MREMAP_MAYMOVE);
            if (buffer == MAP_FAILED) {
                ucm_fatal("failed to allocate maps buffer(size=%zu)", buffer_size);
            }
            buffer_size *= 2;

            /* read again from the beginning of the file */
            ret = lseek(maps_fd, 0, SEEK_SET);
            if (ret < 0) {
               ucm_fatal("failed to lseek(0): %m");
            }
            offset = 0;
        } else if (read_size == 0) {
            /* finished reading */
            buffer[offset] = '\0';
            break;
        } else {
            /* more data could be available even if the buffer is not full */
            offset += read_size;
        }
    }
    pthread_rwlock_unlock(&lock);

    close(maps_fd);

    pthread_rwlock_rdlock(&lock);

    ptr    = buffer;
    while ( (newline = strchr(ptr, '\n')) != NULL ) {
        /* 00400000-0040b000 r-xp ... \n */
        ret = sscanf(ptr, "%lx-%lx %4c", &start, &end, prot_c);
        if (ret != 3) {
            ucm_fatal("failed to parse %s error at offset %zd",
                      UCM_PROC_SELF_MAPS, ptr - buffer);
        }

        prot = 0;
        if (prot_c[0] == 'r') {
            prot |= PROT_READ;
        }
        if (prot_c[1] == 'w') {
            prot |= PROT_WRITE;
        }
        if (prot_c[2] == 'x') {
            prot |= PROT_EXEC;
        }

        if (cb(arg, (void*)start, end - start, prot)) {
            goto out;
        }

        ptr = newline + 1;
    }

out:
    pthread_rwlock_unlock(&lock);
}

typedef struct {
    const void   *shmaddr;
    size_t       seg_size;
} ucm_get_shm_seg_size_ctx_t;

static int ucm_get_shm_seg_size_cb(void *arg, void *addr, size_t length, int prot)
{
    ucm_get_shm_seg_size_ctx_t *ctx = arg;
    if (addr == ctx->shmaddr) {
        ctx->seg_size = length;
        return 1;
    }
    return 0;
}

size_t ucm_get_shm_seg_size(const void *shmaddr)
{
    ucm_get_shm_seg_size_ctx_t ctx = { shmaddr, 0 };
    ucm_parse_proc_self_maps(ucm_get_shm_seg_size_cb, &ctx);
    return ctx.seg_size;
}
