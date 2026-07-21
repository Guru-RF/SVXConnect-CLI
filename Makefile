# SVXConnect-CLI — a terminal client for SvxLink reflectors.
# SPDX-License-Identifier: GPL-3.0-or-later
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
CFLAGS   += -Isrc -Ithird_party
CPPFLAGS ?=
LDFLAGS  ?=

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

.PHONY: all clean install uninstall asan
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
