# SVXConnect-CLI — a terminal client for SvxLink reflectors.
# SPDX-License-Identifier: MIT
#
# Build targets: macOS (Homebrew) and Debian / Raspberry Pi OS / Ubuntu.
#
#   make                 build build/svxconnect
#   make install         install to $(PREFIX)/bin      (PREFIX=/usr/local)
#   make asan            build with AddressSanitizer + UBSan
#   make clean

CC       ?= cc
# gnu11 (not c11): on glibc, strict -std=c11 sets __STRICT_ANSI__ and hides BSD/
# POSIX declarations (clock_gettime, getaddrinfo, strncasecmp, ns_*, ...).
CFLAGS   ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11
CPPFLAGS ?=
LDFLAGS  ?=

# `override`, because a variable set on the command line (make CFLAGS="-fsanitize=...")
# otherwise beats every assignment in this file, including `+=` — which would
# silently drop the include path and break the build in a confusing way.
override CFLAGS += -Isrc -Ithird_party
# snprintf is bounded and always NUL-terminates, so a truncated diagnostic
# string (a clipped host name in an error, say) is harmless by construction.
# gcc's -Wformat-truncation flags exactly that safe pattern; clang does not
# enable it at all. Turn it off so the two compilers agree and the build stays
# warning-clean on both.
override CFLAGS += -Wno-format-truncation

BUILD  := build
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BIN    := svxconnect

UNAME_S := $(shell uname -s)

# ---------------------------------------------------------------- platform

ifeq ($(UNAME_S),Darwin)
    BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
    ifeq ($(BREW_PREFIX),)
        BREW_PREFIX := /opt/homebrew
    endif
    # openssl@3 is keg-only on macOS, hence the explicit opt/ path. The
    # Homebrew formula passes OPENSSL_PREFIX so we never shell out to `brew`
    # inside the build sandbox.
    OPENSSL_PREFIX ?= $(BREW_PREFIX)/opt/openssl@3
    CPPFLAGS += -I$(BREW_PREFIX)/include -I$(OPENSSL_PREFIX)/include
    LDFLAGS  += -L$(BREW_PREFIX)/lib     -L$(OPENSSL_PREFIX)/lib
    PLATFORM_LIBS := -framework CoreFoundation -framework CoreAudio \
                     -framework AudioUnit -framework AudioToolbox \
                     -framework AVFoundation -framework Foundation
    # NSMicrophoneUsageDescription must be reachable from the Mach-O or macOS
    # has no string to show in the TCC prompt. See docs/TCC.md.
    ifneq ($(wildcard packaging/macos/Info.plist),)
        LDFLAGS += -sectcreate __TEXT __info_plist packaging/macos/Info.plist
    endif
    POSTLINK = codesign -s - --force $@ 2>/dev/null || true
else
    # miniaudio dlopen()s libasound.so.2 / libpulse.so.0 at runtime, so there
    # is deliberately no -dev package to install for audio.
    PLATFORM_LIBS := -lpthread -ldl
    POSTLINK      = :
    # glibc hides strcasestr, strncasecmp and the BSD string helpers behind
    # feature macros; macOS exposes them unconditionally. _GNU_SOURCE turns
    # them on. Without it the Linux build fails to compile (implicit
    # declaration of strcasestr) — the single most likely portability break,
    # since the project has so far only been built on macOS.
    CPPFLAGS += -D_GNU_SOURCE
endif

# ------------------------------------------------------------- pkg-config

pc = $(shell pkg-config --$(2) $(1) 2>/dev/null)

OPUS_CFLAGS := $(call pc,opus,cflags)
OPUS_LIBS   := $(call pc,opus,libs)
ifeq ($(strip $(OPUS_LIBS)),)
    OPUS_LIBS := -lopus
endif
CPPFLAGS += $(OPUS_CFLAGS)

# ncursesw first (Debian splits narrow/wide), then ncurses, then bare
# -lncurses: macOS ships a merged narrow+wide libncurses 6.0 and has no .pc.
NCURSES_CFLAGS := $(call pc,ncursesw,cflags)
NCURSES_LIBS   := $(call pc,ncursesw,libs)
ifeq ($(strip $(NCURSES_LIBS)),)
    NCURSES_CFLAGS := $(call pc,ncurses,cflags)
    NCURSES_LIBS   := $(call pc,ncurses,libs)
endif
ifeq ($(strip $(NCURSES_LIBS)),)
    NCURSES_LIBS := -lncurses
endif
CPPFLAGS += $(NCURSES_CFLAGS)

LDLIBS := -lssl -lcrypto -lresolv $(OPUS_LIBS) $(NCURSES_LIBS) -lm $(PLATFORM_LIBS)

# ---------------------------------------------------------------- sources

CSRC := $(shell find src -name '*.c' 2>/dev/null | sort)
ifeq ($(UNAME_S),Darwin)
    MSRC := $(shell find src -name '*.m' 2>/dev/null | sort)
else
    MSRC :=
endif

OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CSRC)) $(patsubst %.m,$(BUILD)/%.o,$(MSRC))
DEP := $(OBJ:.o=.d)

.PHONY: all clean install uninstall asan test
all: $(BUILD)/$(BIN)

$(BUILD)/$(BIN): $(OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@$(POSTLINK)

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/%.o: %.m
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -fobjc-arc -MMD -MP -c -o $@ $<

# miniaudio is a ~95k-line vendored header; it will not survive -Wall -Wextra,
# so relax the warnings for that one translation unit only.
$(BUILD)/src/audio/dev_miniaudio.o: CFLAGS += -Wno-unused-function -Wno-unused-variable \
                                              -Wno-sign-compare -Wno-unused-but-set-variable

# example.conf, embedded as a C string for --init-config. Each line becomes a
# "...\n" literal with \ and " escaped. sed, because it is on every build host
# as-is — xxd is not on a bare Debian.
GEN := $(BUILD)/gen

$(GEN)/example_conf.inc: example.conf
	@mkdir -p $(@D)
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$$/\\n"/' $< > $@

$(BUILD)/src/main.o $(BUILD)/tests/conftest.o: $(GEN)/example_conf.inc
$(BUILD)/src/main.o $(BUILD)/tests/conftest.o: CPPFLAGS += -I$(GEN)

# Unit tests. Only the pure-logic modules are covered: the talkgroup
# preemption rules, which have no I/O and are where a subtle mistake is both
# most likely and least visible; and the --init-config renderer, which writes
# into a file the user owns.
CONF_TEST_OBJ := $(BUILD)/tests/conftest.o \
                 $(BUILD)/src/common/conftemplate.o \
                 $(BUILD)/src/common/config.o \
                 $(BUILD)/src/common/log.o \
                 $(BUILD)/src/common/util.o

$(BUILD)/conftest: $(CONF_TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lm

TEST_OBJ := $(BUILD)/tests/tgtest.o \
            $(BUILD)/src/tg/tgmanager.o \
            $(BUILD)/src/common/config.o \
            $(BUILD)/src/common/log.o \
            $(BUILD)/src/common/util.o

$(BUILD)/tgtest: $(TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lm

CRYPTO_TEST_OBJ := $(BUILD)/tests/cryptotest.o \
                   $(BUILD)/src/common/crypto.o \
                   $(BUILD)/src/common/util.o

$(BUILD)/cryptotest: $(CRYPTO_TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lssl -lcrypto -lm

test: $(BUILD)/tgtest $(BUILD)/cryptotest $(BUILD)/conftest
	@$(BUILD)/tgtest
	@$(BUILD)/cryptotest
	@$(BUILD)/conftest

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -Wall -Wextra -std=gnu11 -fsanitize=address,undefined -fno-omit-frame-pointer"

install: $(BUILD)/$(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BUILD)/$(BIN) $(DESTDIR)$(BINDIR)
	@echo "Installed: $(BIN) -> $(DESTDIR)$(BINDIR)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -rf $(BUILD)

-include $(DEP)
