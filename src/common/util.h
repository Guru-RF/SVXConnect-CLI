/* SPDX-License-Identifier: MIT
 * SVXConnect-CLI — Copyright (c) 2026 Joeri Van Dooren
 *
 * Small helpers: big-endian accessors, monotonic clock, file and string utils.
 */
#ifndef SVX_UTIL_H
#define SVX_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Big-endian helpers — the reflector protocol is big-endian throughout. */
static inline void be_put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static inline void be_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static inline uint16_t be_get_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t be_get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef CLAMP
#define CLAMP(x, lo, hi) MIN(MAX((x), (lo)), (hi))
#endif

/* Monotonic milliseconds. The single clock source for every timer in this
 * program — never mix in time(2) for deltas, it steps on NTP correction. */
uint64_t now_ms(void);

/* Sleep milliseconds, EINTR-safe. */
void msleep(unsigned ms);

/* Read an entire file. Returns a malloc'd NUL-terminated buffer; *len excludes
 * the NUL. Caller frees. Returns NULL on error. */
char *read_file(const char *path, size_t *len);

/* Write a whole file atomically (write to .tmp, then rename). mode is applied
 * to the temp file before the rename, so the file is never briefly world
 * readable — this matters for private keys. */
int write_file_atomic(const char *path, const void *data, size_t len, int mode);

/* The same, without the fsync(). Readers still only ever see the old or the
 * new contents, but after a crash the file may be empty or stale. For
 * advisory files rewritten constantly from the main loop (the status file),
 * where an fsync every second stalls audio and heartbeats behind disk I/O. */
int write_file_replace(const char *path, const void *data, size_t len, int mode);

/* mkdir -p */
int mkdir_p(const char *path, int mode);

/* Trim ASCII whitespace. Returns a pointer into s (not necessarily s). */
char *str_trim(char *s);

/* Uppercase in place. */
void str_upper(char *s);

/* Case-insensitive compare, locale-independent (no strcasecmp locale traps). */
int  str_ieq(const char *a, const char *b);

/* Expand a leading "~/" to $HOME. Always NUL-terminates dst. Returns dst. */
char *path_expand(char *dst, size_t cap, const char *src);

/* Strip an SSID suffix: "ON6URE-7" -> "ON6URE". Also uppercases. Used to
 * compare talker callsigns, which the reflector may or may not decorate. */
void call_strip_ssid(char *dst, size_t cap, const char *src);

/* Maidenhead grid locator (6 char, e.g. "JO11ug") from decimal degrees.
 * Writes "" if lat/lon are both exactly 0 (treated as "no fix"). */
void maidenhead(char *dst, size_t cap, double lat, double lon);

/* Format a duration as "0:07" / "12:34" / "1:02:03". */
void fmt_duration(char *dst, size_t cap, uint64_t seconds);

/* Format an age as "12s" / "4m" / "2h" / "--" (0 == never). */
void fmt_age(char *dst, size_t cap, uint64_t ms_ago);

#endif
