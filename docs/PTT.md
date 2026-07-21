# PTT in a terminal

**Short version: SPACE is a toggle. Press it to transmit, press it again to
stop. ESC always stops. `tx_timeout_sec` un-keys you if you forget.**

This document explains why, because "spacebar = push to talk" is the obvious
thing to want and it is worth knowing exactly why it is not what you get.

## A terminal has no key-up event

A terminal emulator does not hand a program key events. It hands it a stream of
*characters* over a pseudo-terminal. Even in raw mode (`cbreak()` + `noecho()`,
which is what SVXConnect uses), pressing SPACE delivers one byte, `0x20`. There
is no corresponding byte when you let go. There is no modifier state. There is
no way to tell "held down" from "pressed quickly".

The only trace of a held key is the operating system's **auto-repeat**: hold
SPACE and more `0x20` bytes arrive. So you could try to infer the release from
the repeats stopping. Two things make that unreliable enough to reject as a
default:

1. **The initial repeat delay is not the repeat interval.** macOS waits about
   500 ms before the first repeat, then sends one roughly every 33 ms. Linux
   is typically 250–660 ms, then 25–40 ms. So the gap after the *first* SPACE
   is ~500 ms, not ~33 ms. A release timeout short enough to feel responsive
   un-keys you a third of a second into every transmission and chops the first
   syllable off every over. A timeout long enough to survive the initial delay
   adds half a second of dead air to the end of every over.

2. **Auto-repeat can be switched off entirely.** macOS System Settings →
   Keyboard → Key Repeat → Off, and `xset r off` on Linux, are both real
   settings that real people use. With repeat off, hold-to-talk transmits for
   exactly one timeout period and then stops, no matter how long you hold the
   key.

It also degrades badly over SSH (repeats arrive bunched by network latency),
inside tmux and screen (which re-emit input), and in terminals that buffer.

## Why not read the keyboard directly?

True key-down/key-up is possible, but not for free:

- **macOS** — `CGEventTap` or `IOHIDManager`, both of which require the
  **Input Monitoring** privacy permission. That is a *second* system permission
  dialog on top of the microphone one, it is a global keyboard hook (so it sees
  everything you type in every application), and it does not work over SSH.
- **Linux** — reading `/dev/input/event*` directly, which needs your user in
  the `input` group or root, and does not work over SSH either.

One permission prompt for the microphone is already a rough edge. Two, for a
global keyboard hook, is worse than the problem it solves.

## What you get instead

**Toggle.** It is deterministic. It works over SSH, in tmux, at any latency,
with key repeat on or off, in every terminal. The risk it carries — walking
away from a keyed transmitter — is handled directly:

- `tx_timeout_sec` (default **120**) hard un-keys and beeps. The last 15
  seconds show a red countdown in the PTT bar.
- **ESC** always un-keys, whatever else is on screen. Panic release.
- The PTT bar is full-width reverse red with a running timer while you are
  transmitting. You will not miss it.

## Real push-to-talk: the control FIFO

For an actual PTT switch, use the control FIFO. `ctl_fifo` in the config
(default `~/.local/state/svxconnect/ctl`) is a named pipe that SVXConnect reads
alongside the keyboard:

```sh
echo "ptt on"  > ~/.local/state/svxconnect/ctl
echo "ptt off" > ~/.local/state/svxconnect/ctl
```

Full verb list:

```
ptt on | ptt off | ptt toggle
tg <n> | tg next | tg prev
lock on | lock off | lock toggle
mute <n> | unmute <n>
volume <0-100>
quit
```

### Example: a foot switch on a Raspberry Pi GPIO

```sh
#!/bin/sh
# GPIO 17, active high. `sudo apt install gpiod`
CTL=~/.local/state/svxconnect/ctl
gpiomon -b -F "%e" gpiochip0 17 | while read -r edge; do
    case "$edge" in
        1) echo "ptt on"  > "$CTL" ;;
        0) echo "ptt off" > "$CTL" ;;
    esac
done
```

### Example: a window-manager hotkey

Bind key-press and key-release separately — this is what a window manager can
do and a terminal cannot. For i3:

```
bindsym --release F12 exec echo "ptt off" > ~/.local/state/svxconnect/ctl
bindsym           F12 exec echo "ptt on"  > ~/.local/state/svxconnect/ctl
```

The FIFO is also how you test transmit before touching the interface, and how
you script an unattended node.
