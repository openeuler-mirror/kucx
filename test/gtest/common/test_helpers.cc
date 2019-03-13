/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2012.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "test_helpers.h"

#include <ucs/sys/math.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/string.h>
#include <sys/resource.h>

namespace ucs {

const double test_timeout_in_sec = 60.;

const double watchdog_timeout_default = 900.; // 15 minutes

static test_watchdog_t watchdog;

void *watchdog_func(void *arg)
{
    int ret = 0;
    double now;
    struct timespec timeout;

    pthread_mutex_lock(&watchdog.mutex);

    /* sync with parent thread */
    pthread_barrier_wait(&watchdog.barrier);

    do {
        now = ucs_get_accurate_time();
        ucs_sec_to_timespec(now + watchdog.timeout, &timeout);

        ret = pthread_cond_timedwait(&watchdog.cv, &watchdog.mutex, &timeout);
        if (!ret) {
            pthread_barrier_wait(&watchdog.barrier);
        }
    } while (!ret && (watchdog.state == test_watchdog_t::WATCHDOG_RUNNING));

    if (ret) {
        if (ret == ETIMEDOUT) {
            ADD_FAILURE() << "Timeout expired - abort";
            pthread_kill(watchdog.parent_thread, SIGABRT);
        } else {
            ADD_FAILURE() << "Watchdog fails " << ret;
            abort();
        }
    }

    pthread_mutex_unlock(&watchdog.mutex);

    return NULL;
}

void watchdog_signal()
{
    pthread_mutex_lock(&watchdog.mutex);
    pthread_cond_signal(&watchdog.cv);
    pthread_mutex_unlock(&watchdog.mutex);

    pthread_barrier_wait(&watchdog.barrier);
}

void watchdog_time_set(double new_timeout)
{
    pthread_mutex_lock(&watchdog.mutex);
    /* change timeout value */
    watchdog.timeout = new_timeout;
    /* apply new value for timeout */
    watchdog_signal();
    pthread_mutex_unlock(&watchdog.mutex);
}

void watchdog_time_reset()
{
    watchdog_time_set(watchdog_timeout_default);
}

void watchdog_start()
{
    pthread_mutexattr_t mutex_attr;

    pthread_mutexattr_init(&mutex_attr);
    /* create reentrant mutex */
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&watchdog.mutex, NULL);
    pthread_mutexattr_destroy(&mutex_attr);

    pthread_cond_init(&watchdog.cv, NULL);

    pthread_barrier_init(&watchdog.barrier, NULL, 2); // 2 - parent thread + watchdog

    pthread_mutex_lock(&watchdog.mutex);
    watchdog.state         = test_watchdog_t::WATCHDOG_RUNNING;
    watchdog.timeout       = watchdog_timeout_default;
    watchdog.parent_thread = pthread_self();
    pthread_mutex_unlock(&watchdog.mutex);

    pthread_create(&watchdog.thread, NULL, watchdog_func, NULL);

    /* sync with watchdog thread */
    pthread_barrier_wait(&watchdog.barrier);

    /* test signaling */
    watchdog_signal();
}

void watchdog_stop()
{
    void *ret_val;

    pthread_mutex_lock(&watchdog.mutex);
    watchdog.state = test_watchdog_t::WATCHDOG_STOPPED;
    pthread_cond_signal(&watchdog.cv);
    pthread_mutex_unlock(&watchdog.mutex);

    pthread_barrier_wait(&watchdog.barrier);
    pthread_join(watchdog.thread, &ret_val);

    pthread_barrier_destroy(&watchdog.barrier);
    pthread_cond_destroy(&watchdog.cv);
    pthread_mutex_destroy(&watchdog.mutex);
}

int test_time_multiplier()
{
    int factor = 1;
#if _BullseyeCoverage
    factor *= 10;
#endif
    if (RUNNING_ON_VALGRIND) {
        factor *= 20;
    }
    return factor;
}

ucs_time_t get_deadline(double timeout_in_sec)
{
    return ucs_get_time() + ucs_time_from_sec(timeout_in_sec *
                                              test_time_multiplier());
}

int max_tcp_connections()
{
    int max_conn = 65535 - 1024; /* limit on number of ports */

    /* Limit numer of endpoints to number of open files, for TCP */
    struct rlimit rlim;
    int ret = getrlimit(RLIMIT_NOFILE, &rlim);
    if (ret == 0) {
        /* assume no more than 100 fd-s are already used */
        max_conn = ucs_min((static_cast<int>(rlim.rlim_cur) - 100) / 2, max_conn);
    }

    return max_conn;
}

void fill_random(void *data, size_t size)
{
    if (ucs::test_time_multiplier() > 1) {
        memset(data, 0, size);
        return;
    }

    uint64_t seed = rand();
    for (size_t i = 0; i < size / sizeof(uint64_t); ++i) {
        ((uint64_t*)data)[i] = seed;
        seed = seed * 10 + 17;
    }
    size_t remainder = size % sizeof(uint64_t);
    memset((char*)data + size - remainder, 0xab, remainder);
}

scoped_setenv::scoped_setenv(const char *name, const char *value) : m_name(name) {
    if (getenv(name)) {
        m_old_value = getenv(name);
    }
    setenv(m_name.c_str(), value, 1);
}

scoped_setenv::~scoped_setenv() {
    if (!m_old_value.empty()) {
        setenv(m_name.c_str(), m_old_value.c_str(), 1);
    } else {
        unsetenv(m_name.c_str());
    }
}

void safe_sleep(double sec) {
    ucs_time_t current_time = ucs_get_time();
    ucs_time_t end_time = current_time + ucs_time_from_sec(sec);

    while (current_time < end_time) {
        usleep((long)ucs_time_to_usec(end_time - current_time));
        current_time = ucs_get_time();
    }
}

void safe_usleep(double usec) {
    safe_sleep(usec * 1e-6);
}

bool is_inet_addr(const struct sockaddr* ifa_addr) {
    return (ifa_addr->sa_family == AF_INET) ||
           (ifa_addr->sa_family == AF_INET6);
}

bool is_rdmacm_netdev(const char *ifa_name) {
    struct dirent *entry;
    char path[PATH_MAX];
    char dev_name[16];
    char guid_buf[32];
    DIR *dir;

    snprintf(path, PATH_MAX, "/sys/class/net/%s/device/infiniband", ifa_name);
    dir = opendir(path);
    if (dir == NULL) {
        return false;
    }

    /* read IB device name */
    for (;;) {
        entry = readdir(dir);
        if (entry == NULL) {
            closedir(dir);
            return false;
        } else if (entry->d_name[0] != '.') {
            ucs_strncpy_zero(dev_name, entry->d_name, sizeof(dev_name));
            break;
        }
    }
    closedir(dir);

    /* read node guid */
    memset(guid_buf, 0, sizeof(guid_buf));
    ssize_t nread = ucs_read_file(guid_buf, sizeof(guid_buf), 1,
                                  "/sys/class/infiniband/%s/node_guid", dev_name);
    if (nread < 0) {
        return false;
    }

    /* use the device if node_guid != 0 */
    return strstr(guid_buf, "0000:0000:0000:0000") == NULL;
}

uint16_t get_port() {
    int sock_fd, ret;
    ucs_status_t status;
    struct sockaddr_in addr_in, ret_addr;
    socklen_t len = sizeof(ret_addr);
    uint16_t port;

    status = ucs_socket_create(AF_INET, SOCK_STREAM, &sock_fd);
    EXPECT_EQ(status, UCS_OK);

    memset(&addr_in, 0, sizeof(struct sockaddr_in));
    addr_in.sin_family      = AF_INET;
    addr_in.sin_addr.s_addr = INADDR_ANY;

    do {
        addr_in.sin_port        = htons(0);
        /* Ports below 1024 are considered "privileged" (can be used only by
         * user root). Ports above and including 1024 can be used by anyone */
        ret = bind(sock_fd, (struct sockaddr*)&addr_in,
                   sizeof(struct sockaddr_in));
    } while (ret);

    ret = getsockname(sock_fd, (struct sockaddr*)&ret_addr, &len);
    EXPECT_EQ(ret, 0);
    EXPECT_LT(1023, ntohs(ret_addr.sin_port)) ;

    port = ret_addr.sin_port;
    close(sock_fd);
    return port;
}

void *mmap_fixed_address() {
    return (void*)0xff0000000;
}

namespace detail {

message_stream::message_stream(const std::string& title) {
    static const char PADDING[] = "          ";
    static const size_t WIDTH = strlen(PADDING);

    msg <<  "[";
    msg.write(PADDING, ucs_max(WIDTH - 1, title.length()) - title.length());
    msg << title << " ] ";
}

message_stream::~message_stream() {
    msg << std::endl;
    std::cout << msg.str() << std::flush;
}

} // detail

} // ucs
