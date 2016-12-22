/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2011.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "async_int.h"

#include <ucs/arch/atomic.h>
#include <ucs/debug/debug.h>
#include <ucs/datastruct/khash.h>


#define UCS_ASYNC_TIMER_ID_MIN      1000000u
#define UCS_ASYNC_TIMER_ID_MAX      2000000u

#define UCS_ASYNC_HANDLER_FMT       "%p [id=%d]"
#define UCS_ASYNC_HANDLER_ARG(_h)   (_h), (_h)->id

/* Hash table for all event and timer handlers */
KHASH_MAP_INIT_INT(ucs_async_handler, ucs_async_handler_t *);


typedef struct ucs_async_global_context {
    khash_t(ucs_async_handler)     handlers;
    pthread_rwlock_t               handlers_lock;
    volatile uint32_t              timer_id;
} ucs_async_global_context_t;


static ucs_async_global_context_t ucs_async_global_context = {
    .handlers_lock   = PTHREAD_RWLOCK_INITIALIZER,
    .timer_id        = UCS_ASYNC_TIMER_ID_MIN
};


#define ucs_async_method_call(_mode, _func, ...) \
    ((_mode) == UCS_ASYNC_MODE_SIGNAL) ? ucs_async_signal_ops._func(__VA_ARGS__) : \
    ((_mode) == UCS_ASYNC_MODE_THREAD) ? ucs_async_thread_ops._func(__VA_ARGS__) : \
                                           ucs_async_poll_ops._func(__VA_ARGS__)

#define ucs_async_method_call_all(_func, ...) \
    { \
        ucs_async_signal_ops._func(__VA_ARGS__); \
        ucs_async_thread_ops._func(__VA_ARGS__); \
        ucs_async_poll_ops._func(__VA_ARGS__); \
    }


static ucs_status_t ucs_async_poll_init(ucs_async_context_t *async)
{
    async->poll_block = 0;
    return UCS_OK;
}

static int ucs_async_poll_tryblock(ucs_async_context_t *async)
{
    return 1;
}

static ucs_async_ops_t ucs_async_poll_ops = {
    .init               = ucs_empty_function,
    .cleanup            = ucs_empty_function,
    .block              = ucs_empty_function,
    .unblock            = ucs_empty_function,
    .context_init       = ucs_async_poll_init,
    .context_try_block  = ucs_async_poll_tryblock,
    .context_unblock    = ucs_empty_function,
    .add_event_fd       = ucs_empty_function_return_success,
    .remove_event_fd    = ucs_empty_function_return_success,
    .add_timer          = ucs_empty_function_return_success,
    .remove_timer       = ucs_empty_function_return_success,
};

static inline khiter_t ucs_async_handler_kh_get(int id)
{
    return kh_get(ucs_async_handler, &ucs_async_global_context.handlers, id);
}

static inline int ucs_async_handler_kh_is_end(khiter_t hash_it)
{
    return hash_it == kh_end(&ucs_async_global_context.handlers);
}

static void ucs_async_handler_hold(ucs_async_handler_t *handler)
{
    ucs_atomic_add32(&handler->refcount, 1);
}

/* incremented reference count and return the handler */
static ucs_async_handler_t *ucs_async_handler_get(int id)
{
    ucs_async_handler_t *handler;
    khiter_t hash_it;

    pthread_rwlock_rdlock(&ucs_async_global_context.handlers_lock);
    hash_it = ucs_async_handler_kh_get(id);
    if (ucs_async_handler_kh_is_end(hash_it)) {
        handler = NULL;
        goto out_unlock;
    }

    handler = kh_value(&ucs_async_global_context.handlers, hash_it);
    ucs_assert_always(handler->id == id);
    ucs_async_handler_hold(handler);

out_unlock:
    pthread_rwlock_unlock(&ucs_async_global_context.handlers_lock);
    return handler;
}

static ucs_async_mode_t ucs_async_handler_mode(int id)
{
    ucs_async_mode_t mode;
    khiter_t hash_it;

    pthread_rwlock_rdlock(&ucs_async_global_context.handlers_lock);
    hash_it = ucs_async_handler_kh_get(id);
    if (ucs_async_handler_kh_is_end(hash_it)) {
        mode = UCS_ASYNC_MODE_POLL;
    } else {
        mode = kh_value(&ucs_async_global_context.handlers, hash_it)->mode;
    }
    pthread_rwlock_unlock(&ucs_async_global_context.handlers_lock);
    return mode;
}

/* remove from hash and return the handler */
static ucs_async_handler_t *ucs_async_handler_extract(int id)
{
    ucs_async_handler_t *handler;
    khiter_t hash_it;

    pthread_rwlock_wrlock(&ucs_async_global_context.handlers_lock);
    hash_it = ucs_async_handler_kh_get(id);
    if (ucs_async_handler_kh_is_end(hash_it)) {
        ucs_debug("async handler [id=%d] not found in hash table", id);
        handler = NULL;
    } else {
        handler = kh_value(&ucs_async_global_context.handlers, hash_it);
        ucs_assert_always(handler->id == id);
        kh_del(ucs_async_handler, &ucs_async_global_context.handlers, hash_it);
        ucs_debug("removed async handler " UCS_ASYNC_HANDLER_FMT " from hash",
                  UCS_ASYNC_HANDLER_ARG(handler));
    }
    pthread_rwlock_unlock(&ucs_async_global_context.handlers_lock);

    return handler;
}

/* decrement reference count and release the handler if reached 0 */
static void ucs_async_handler_put(ucs_async_handler_t *handler)
{
    if (ucs_atomic_fadd32(&handler->refcount, -1) > 1) {
        return;
    }

    ucs_debug("release async handler " UCS_ASYNC_HANDLER_FMT,
              UCS_ASYNC_HANDLER_ARG(handler));
    ucs_free(handler);
}

/* add new handler to the table */
static ucs_status_t ucs_async_handler_add(ucs_async_handler_t *handler)
{
    int hash_extra_status;
    ucs_status_t status;
    khiter_t hash_it;

    pthread_rwlock_wrlock(&ucs_async_global_context.handlers_lock);

    ucs_assert_always(handler->refcount == 1);
    hash_it = kh_put(ucs_async_handler, &ucs_async_global_context.handlers,
                     handler->id, &hash_extra_status);
    if (hash_extra_status == -1) {
        ucs_error("Failed to add async handler " UCS_ASYNC_HANDLER_FMT " to hash",
                  UCS_ASYNC_HANDLER_ARG(handler));
        status = UCS_ERR_NO_MEMORY;
        goto out_unlock;
    } else if (hash_extra_status == 0) {
        ucs_error("Async handler " UCS_ASYNC_HANDLER_FMT " already exists",
                  UCS_ASYNC_HANDLER_ARG(handler));
        status = UCS_ERR_ALREADY_EXISTS;
        goto out_unlock;
    }

    ucs_assert_always(!ucs_async_handler_kh_is_end(hash_it));
    kh_value(&ucs_async_global_context.handlers, hash_it) = handler;
    ucs_debug("added async handler " UCS_ASYNC_HANDLER_FMT " to hash",
              UCS_ASYNC_HANDLER_ARG(handler));
    status = UCS_OK;

out_unlock:
    pthread_rwlock_unlock(&ucs_async_global_context.handlers_lock);
    return status;
}

static ucs_status_t ucs_async_handler_dispatch(ucs_async_handler_t *handler)
{
    ucs_async_context_t *async;
    ucs_async_mode_t mode;
    ucs_status_t status;

    mode  = handler->mode;
    async = handler->async;
    if (async != NULL) {
        async->last_wakeup = ucs_get_time();
    }
    if (async == NULL) {
        ucs_trace_async("calling async handler " UCS_ASYNC_HANDLER_FMT,
                        UCS_ASYNC_HANDLER_ARG(handler));
        handler->cb(handler->arg);
    } else if (ucs_async_method_call(mode, context_try_block, async)) {
        ucs_trace_async("calling async handler " UCS_ASYNC_HANDLER_FMT,
                        UCS_ASYNC_HANDLER_ARG(handler));
        handler->cb(handler->arg);
        ucs_async_method_call(mode, context_unblock, async);
    } else /* async != NULL */ {
        ucs_trace_async("missed " UCS_ASYNC_HANDLER_FMT ", last_wakeup %llu",
                        UCS_ASYNC_HANDLER_ARG(handler), async->last_wakeup);
        if (ucs_atomic_cswap32(&handler->missed, 0, 1) == 0) {
            status = ucs_mpmc_queue_push(&async->missed, handler->id);
            if (status != UCS_OK) {
                ucs_fatal("Failed to push event %d to miss queue: %s",
                          handler->id, ucs_status_string(status));
            }
        }
        return UCS_ERR_NO_PROGRESS;
    }
    return UCS_OK;
}

ucs_status_t ucs_async_dispatch_handlers(int *events, size_t count)
{
    ucs_status_t status = UCS_OK, tmp_status;
    ucs_async_handler_t *handler;

    for (; count > 0; --count, ++events) {
        handler = ucs_async_handler_get(*events);
        if (handler == NULL) {
            ucs_trace_async("handler for %d not found - ignoring", *events);
            continue;
        }

        tmp_status = ucs_async_handler_dispatch(handler);
        if (tmp_status != UCS_OK) {
            status = tmp_status;
        }

        ucs_async_handler_put(handler);
    }
    return status;
}

ucs_status_t ucs_async_dispatch_timerq(ucs_timer_queue_t *timerq,
                                       ucs_time_t current_time)
{
    size_t num_timers = 0;
    int *expired_timers;
    ucs_timer_t *timer;

    expired_timers = ucs_alloca(ucs_timerq_size(timerq) * sizeof(*expired_timers));
    ucs_timerq_for_each_expired(timer, timerq, current_time) {
        expired_timers[num_timers++] = timer->id;
    }
    return ucs_async_dispatch_handlers(expired_timers, num_timers);
}

ucs_status_t ucs_async_context_init(ucs_async_context_t *async, ucs_async_mode_t mode)
{
    ucs_status_t status;

    ucs_trace_func("async=%p", async);

    status = ucs_mpmc_queue_init(&async->missed, ucs_global_opts.async_max_events);
    if (status != UCS_OK) {
        goto err;
    }

    status = ucs_async_method_call(mode, context_init, async);
    if (status != UCS_OK) {
        goto err_free_miss_fds;
    }

    async->mode         = mode;
    async->num_handlers = 0;
    async->last_wakeup  = ucs_get_time();
    return UCS_OK;

err_free_miss_fds:
    ucs_mpmc_queue_cleanup(&async->missed);
err:
    return status;
}

void ucs_async_context_cleanup(ucs_async_context_t *async)
{
    ucs_trace_func("async=%p", async);

    if (async->num_handlers > 0) {
        ucs_warn("releasing async context with %d handlers", async->num_handlers);
    }
    ucs_mpmc_queue_cleanup(&async->missed);
}

static ucs_status_t ucs_async_alloc_handler(ucs_async_mode_t mode, int id,
                                            ucs_async_event_cb_t cb, void *arg,
                                            ucs_async_context_t *async)
{
    ucs_async_handler_t *handler;
    ucs_status_t status;

    /* If async context is given, it should have same mode */
    if ((async != NULL) && (async->mode != mode)) {
        ucs_error("Async mode mismatch for handler [id=%d], "
                  "mode: %d async context mode: %d", id, mode, async->mode);
        status = UCS_ERR_INVALID_PARAM;
        goto err;
    }

    /* Limit amount of handlers per context */
    if (async != NULL) {
        if (ucs_atomic_fadd32(&async->num_handlers, +1) >= ucs_global_opts.async_max_events) {
            status = UCS_ERR_EXCEEDS_LIMIT;
            goto err_dec_num_handlers;
        }
    }

    handler = ucs_malloc(sizeof *handler, "async handler");
    if (handler == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    handler->id       = id;
    handler->mode     = mode;
    handler->cb       = cb;
    handler->arg      = arg;
    handler->async    = async;
    handler->missed   = 0;
    handler->refcount = 1;
    ucs_async_method_call(mode, block);
    status = ucs_async_handler_add(handler);
    ucs_async_method_call(mode, unblock);
    if (status != UCS_OK) {
        goto err_free;
    }

    return UCS_OK;

err_free:
    ucs_free(handler);
err_dec_num_handlers:
    if (async != NULL) {
        ucs_atomic_add32(&async->num_handlers, -1);
    }
err:
    return status;
}

ucs_status_t ucs_async_set_event_handler(ucs_async_mode_t mode, int event_fd,
                                         int events, ucs_async_event_cb_t cb,
                                         void *arg, ucs_async_context_t *async)
{
    ucs_status_t status;

    if (event_fd >= UCS_ASYNC_TIMER_ID_MIN) {
        /* File descriptor too large */
        status = UCS_ERR_EXCEEDS_LIMIT;
        goto err;
    }

    status = ucs_async_alloc_handler(mode, event_fd, cb, arg, async);
    if (status != UCS_OK) {
        goto err;
    }

    status = ucs_async_method_call(mode, add_event_fd, async, event_fd, events);
    if (status != UCS_OK) {
        goto err_remove_handler;
    }

    ucs_debug("listening to async event fd %d events 0x%x mode %s", event_fd,
              events, ucs_async_mode_names[mode]);
    return UCS_OK;

err_remove_handler:
    ucs_async_remove_handler(event_fd, 1);
err:
    return status;
}

ucs_status_t ucs_async_add_timer(ucs_async_mode_t mode, ucs_time_t interval,
                                 ucs_async_event_cb_t cb, void *arg,
                                 ucs_async_context_t *async, int *timer_id_p)
{
    ucs_status_t status;
    int timer_id;

    /* Search for unused timer ID */
    do {
        timer_id = ucs_atomic_fadd32(&ucs_async_global_context.timer_id, 1);
        if (timer_id >= UCS_ASYNC_TIMER_ID_MAX) {
            timer_id = UCS_ASYNC_TIMER_ID_MIN;
        }

        status = ucs_async_alloc_handler(mode, timer_id, cb, arg, async);
    } while (status == UCS_ERR_ALREADY_EXISTS);
    if (status != UCS_OK) {
        goto err;
    }

    status = ucs_async_method_call(mode, add_timer, async, timer_id, interval);
    if (status != UCS_OK) {
        goto err_remove_handler;
    }

    *timer_id_p = timer_id;
    return UCS_OK;

err_remove_handler:
    ucs_async_remove_handler(timer_id, 1);
err:
    return status;
}

ucs_status_t ucs_async_remove_handler(int id, int sync)
{
    ucs_async_mode_t mode = ucs_async_handler_mode(id);
    ucs_async_handler_t *handler;
    ucs_status_t status;

    ucs_async_method_call(mode, block);
    handler = ucs_async_handler_extract(id);
    ucs_async_method_call(mode, unblock);
    if (handler == NULL) {
        return UCS_ERR_NO_ELEM;
    }

    ucs_debug("removing async handler " UCS_ASYNC_HANDLER_FMT,
              UCS_ASYNC_HANDLER_ARG(handler));
    if (handler->id >= UCS_ASYNC_TIMER_ID_MIN) {
        status = ucs_async_method_call(handler->mode, remove_timer,
                                       handler->async, handler->id);
    } else {
        status = ucs_async_method_call(handler->mode, remove_event_fd,
                                       handler->async, handler->id);
    }
    if (status != UCS_OK) {
        ucs_warn("failed to remove async handler " UCS_ASYNC_HANDLER_FMT " : %s",
                  UCS_ASYNC_HANDLER_ARG(handler), ucs_status_string(status));
    }

    if (handler->async != NULL) {
        ucs_atomic_add32(&handler->async->num_handlers, -1);
    }

    if (sync) {
        while (handler->refcount > 1) {
            /* TODO use pthread_cond / futex to reduce CPU usage while waiting
             * for the async handler to complete */
            sched_yield();
        }
    }

    ucs_async_handler_put(handler);
    return UCS_OK;
}

void __ucs_async_poll_missed(ucs_async_context_t *async)
{
    ucs_async_handler_t *handler;
    ucs_status_t status;
    uint32_t value;

    ucs_trace_async("miss handler");

    while (!ucs_mpmc_queue_is_empty(&async->missed)) {

        status = ucs_mpmc_queue_pull(&async->missed, &value);
        if (status == UCS_ERR_NO_PROGRESS) {
            /* TODO we should retry here if the code is change to check miss
             * only during ASYNC_UNBLOCK */
            break;
        }

        ucs_async_method_call_all(block);
        handler = ucs_async_handler_get(value);
        if (handler != NULL) {
            ucs_trace_async("calling missed async handler " UCS_ASYNC_HANDLER_FMT,
                            UCS_ASYNC_HANDLER_ARG(handler));
            handler->missed = 0;
            handler->cb(handler->arg);
            ucs_async_handler_put(handler);
        }
        ucs_async_method_call_all(unblock);
    }
}

void ucs_async_poll(ucs_async_context_t *async)
{
    ucs_async_handler_t **handlers, *handler;
    size_t i, n;

    ucs_trace_poll("async=%p", async);

    pthread_rwlock_rdlock(&ucs_async_global_context.handlers_lock);
    handlers = ucs_alloca(kh_size(&ucs_async_global_context.handlers) * sizeof(*handlers));
    n = 0;
    kh_foreach_value(&ucs_async_global_context.handlers, handler, {
        if (((async == NULL) || (async == handler->async)) &&  /* Async context match */
            ((handler->async == NULL) || (handler->async->poll_block == 0))) /* Not blocked */
        {
            ucs_async_handler_hold(handler);
            handlers[n++] = handler;
        }
    });
    pthread_rwlock_unlock(&ucs_async_global_context.handlers_lock);

    for (i = 0; i < n; ++i) {
        ucs_async_handler_dispatch(handlers[i]);
        ucs_async_handler_put(handlers[i]);
    }
}

void ucs_async_global_init()
{
    pthread_rwlock_init(&ucs_async_global_context.handlers_lock, NULL);
    kh_init_inplace(ucs_async_handler, &ucs_async_global_context.handlers);
    ucs_async_method_call_all(init);
}

void ucs_async_global_cleanup()
{
    int num_elems = kh_size(&ucs_async_global_context.handlers);
    if (num_elems != 0) {
        ucs_warn("async handler table is not empty during exit (contains %d elems)",
                 num_elems);
    }
    ucs_async_method_call_all(cleanup);
    kh_destroy_inplace(ucs_async_handler, &ucs_async_global_context.handlers);
    pthread_rwlock_destroy(&ucs_async_global_context.handlers_lock);
}
