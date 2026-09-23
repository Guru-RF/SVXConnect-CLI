/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 */
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

uint64_t now_ms(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

void msleep(unsigned ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) { /* continue */ }
}

char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (out_len) *out_len = got;
    return buf;
}

static int write_replace(const char *path, const void *data, size_t len, int mode,
                         int durable) {
    char tmp[1024];
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    /* Create with the final mode directly: a private key must never exist,
     * even for an instant, with looser permissions than it will end up with. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)mode);
    if (fd < 0) return -1;
    /* open() honours the umask; force the exact mode we asked for. */
    if (fchmod(fd, (mode_t)mode) != 0) { close(fd); unlink(tmp); return -1; }

    const uint8_t *p = (const uint8_t *)data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp); return -1; }
        p += n; left -= (size_t)n;
    }
    if (durable && fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0)  { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int write_file_atomic(const char *path, const void *data, size_t len, int mode) {
    return write_replace(path, data, len, mode, 1);
}

int write_file_replace(const char *path, const void *data, size_t len, int mode) {
    return write_replace(path, data, len, mode, 0);
}

int mkdir_p(const char *path, int mode) {
    char buf[1024];
    size_t len = strlen(path);
    if (len >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    memcpy(buf, path, len + 1);
    if (len > 0 && buf[len - 1] == '/') buf[len - 1] = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(buf, (mode_t)mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

char *str_trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

void str_upper(char *s) {
    if (!s) return;
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

int str_ieq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

char *path_expand(char *dst, size_t cap, const char *src) {
    if (cap == 0) return dst;
    if (src && src[0] == '~' && (src[1] == '/' || src[1] == '\0')) {
        const char *home = getenv("HOME");
        if (home && *home) {
            snprintf(dst, cap, "%s%s", home, src + 1);
            return dst;
        }
    }
    snprintf(dst, cap, "%s", src ? src : "");
    return dst;
}

void call_strip_ssid(char *dst, size_t cap, const char *src) {
    if (cap == 0) return;
    size_t i = 0;
    if (src) {
        for (; src[i] && src[i] != '-' && i + 1 < cap; i++) {
            dst[i] = (char)toupper((unsigned char)src[i]);
        }
    }
    dst[i] = '\0';
}

void maidenhead(char *dst, size_t cap, double lat, double lon) {
    if (cap == 0) return;
    dst[0] = '\0';
    /* Exactly (0,0) means "no position configured", not the Gulf of Guinea. */
    if (lat == 0.0 && lon == 0.0) return;
    if (cap < 7) return;
    if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) return;

    double la = lat + 90.0;    /* 0 .. 180 */
    double lo = lon + 180.0;   /* 0 .. 360 */

    int f1 = (int)(lo / 20.0);
    int f2 = (int)(la / 10.0);
    lo -= f1 * 20.0;
    la -= f2 * 10.0;

    int s1 = (int)(lo / 2.0);
    int s2 = (int)(la / 1.0);
    lo -= s1 * 2.0;
    la -= s2 * 1.0;

    int t1 = (int)(lo / (2.0 / 24.0));
    int t2 = (int)(la / (1.0 / 24.0));

    /* Clamp: floating point at an exact pole/meridian can push an index out. */
    f1 = CLAMP(f1, 0, 17); f2 = CLAMP(f2, 0, 17);
    s1 = CLAMP(s1, 0, 9);  s2 = CLAMP(s2, 0, 9);
    t1 = CLAMP(t1, 0, 23); t2 = CLAMP(t2, 0, 23);

    dst[0] = (char)('A' + f1);
    dst[1] = (char)('A' + f2);
    dst[2] = (char)('0' + s1);
    dst[3] = (char)('0' + s2);
    dst[4] = (char)('a' + t1);
    dst[5] = (char)('a' + t2);
    dst[6] = '\0';
}

void fmt_duration(char *dst, size_t cap, uint64_t seconds) {
    if (cap == 0) return;
    uint64_t h = seconds / 3600;
    uint64_t m = (seconds % 3600) / 60;
    uint64_t s = seconds % 60;
    if (h > 0) snprintf(dst, cap, "%llu:%02llu:%02llu",
                        (unsigned long long)h, (unsigned long long)m,
                        (unsigned long long)s);
    else       snprintf(dst, cap, "%llu:%02llu",
                        (unsigned long long)m, (unsigned long long)s);
}

void fmt_age(char *dst, size_t cap, uint64_t ms_ago) {
    if (cap == 0) return;
    if (ms_ago == 0) { snprintf(dst, cap, "--"); return; }
    uint64_t s = ms_ago / 1000;
    if (s < 60)          snprintf(dst, cap, "%llus", (unsigned long long)s);
    else if (s < 3600)   snprintf(dst, cap, "%llum", (unsigned long long)(s / 60));
    else if (s < 86400)  snprintf(dst, cap, "%lluh", (unsigned long long)(s / 3600));
    else                 snprintf(dst, cap, "%llud", (unsigned long long)(s / 86400));
}
