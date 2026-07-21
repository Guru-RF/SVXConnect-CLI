# SVXConnect-CLI

A terminal client for **SvxLink reflectors** (protocol v3 — mTLS, AES-GCM, Opus).
Plain C, ncurses, no GUI. Runs on **macOS** and **Linux** (Raspberry Pi OS,
Debian, Ubuntu).

It is the command-line sibling of the [SVXConnect](https://svxconnect.app) desktop
and mobile apps: connect to a reflector, monitor a set of talkgroups, switch
between them with the arrow keys, and transmit — all from an SSH session or a
terminal window.

> **Status: in development, but it works on the air.** The reflector client,
> certificate enrolment, audio in both directions and the talkgroup manager are
> all done and verified against a live reflector — a full transmit/receive
> round-trip through a parrot talkgroup decodes correctly. The ncurses
> interface is the last piece; until it lands, use `--headless` plus the
> control FIFO. See [Roadmap](#roadmap).

```
┌─ SVXConnect  ON3URE ────────────────────── be.svx.link:5300  ID 42  nodes 7 ── 20:14:07 ─┐
│ ● Connected      RX  50 p/s   TX   0 p/s   loss 0.0%   JO11ug Gent        cert ok 2027-04│
├──────────────────────┬───────────────────────────────────────────────────────────────────┤
│ TG 8            LOCK │ ACTIVE                                                            │
│──────────────────────│  8      ON4XYZ                     12s  ▌███████▌                 │
│ > 8      ++  ● 12s   │  1745   ON7ABC                      3s  ▌██▌                      │
│   1745   +     2m    │                                                                   │
│   8000         --    │ RECENT                                                            │
│   9990   M     --    │  8      ON4ZZZ           1m ago    0:42                           │
│                      │  1745   ON0TEST        14m ago     0:08                           │
├──────────────────────┤                                                                   │
│ MIC ▌██████▌         │                                                                   │
│ SPK ▌████▌           │                                                                   │
│ VOL ████████░░  80%  │                                                                   │
├──────────────────────┴───────────────────────────────────────────────────────────────────┤
│                            ▌  SPACE = TRANSMIT  ▌   idle                                 │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ←/→ tg   ↑ lock   SPACE ptt   m mute   Enter goto   d dev   l log   r reconn   ? help   q│
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

## What it does

- Connects to a SvxLink v3 reflector over mutual TLS, with AES-128-GCM
  encrypted Opus audio over UDP
- Monitors several talkgroups at once and shows who is talking, on which one
- Switches talkgroups automatically by **priority** when someone keys up, or
  manually with ← / →
- **Locks** to one talkgroup (↑) when you do not want to be pulled away
- Transmits with SPACE, or from a script / foot switch via a control FIFO
- Enrols your client certificate with the reflector sysop (`--enroll`)

**Not** included, by design: no map, no reflector web feed, no WebSocket, no
DMR / D-STAR / AMBE transcoding. This is a voice client.

## Install

### macOS (Homebrew)

```sh
brew tap Guru-RF/ham-tools
brew install svxconnect
```

### Linux — Raspberry Pi OS, Debian, Ubuntu

```sh
sudo apt install build-essential pkg-config libncurses-dev libssl-dev libopus-dev
git clone https://github.com/Guru-RF/SVXConnect-CLI
cd SVXConnect-CLI
make
sudo make install
```

There is deliberately **no audio development package to install**: the audio
backend loads `libasound.so.2` / `libpulse.so.0` at runtime if they are there.
On Pi OS Bookworm and Ubuntu 22.04+ that means PipeWire via `pipewire-pulse`,
which is already installed; on older or bare systems it falls back to ALSA.

## First run

```sh
mkdir -p ~/.config/svxconnect
cp example.conf ~/.config/svxconnect/svxconnect.conf
$EDITOR ~/.config/svxconnect/svxconnect.conf

svxconnect --enroll     # send a CSR, wait for the sysop to sign it
svxconnect              # go
```

The config is looked for at `$SVXCONNECT_CONF`, then
`~/.config/svxconnect/svxconnect.conf` (or `$XDG_CONFIG_HOME/svxconnect/…`),
then `/etc/svxconnect/svxconnect.conf` — or pass one explicitly with
`svxconnect -c <file>`. If none is found, svxconnect prints the exact path to
create. `svxconnect --dump-config` prints every setting with its resolved value.

## Configuration

Everything lives in one file; see [example.conf](example.conf) for the fully
commented version. The talkgroup part is the interesting bit:

```ini
# '+' suffixes set priority:  8 = normal,  8+ = higher,  8++ = highest
switchable = 8, 1745, 8000        # what ←/→ cycles through, in this order
monitored  = 8++, 1745+, 8000, 9990   # everything you want to hear

default_tg     = 8
linger_seconds = 30    # hold a talkgroup this long after an over, so a QSO
                       # is not interrupted by a higher-priority talkgroup
idle_seconds   = 60    # silence everywhere this long -> drop to monitor-only
```

A talker on a higher-priority talkgroup pulls you over automatically. Priority 0
never interrupts a talkgroup that is already busy. Press PageDown to lock and
stop all automatic switching.

## Keys

| Key | Action |
|---|---|
| `↑` `↓` | previous / next talkgroup — or move the cursor in a focused pane |
| `←` `→` | output volume down / up |
| `PageDown` | lock / unlock the talkgroup (no automatic switching) |
| `SPACE` | transmit — **toggle**: press to start, press again to stop |
| `ESC` | stop transmitting immediately |
| `1`–`9` | jump to the Nth switchable talkgroup |
| `Tab` `⇧Tab` | focus the talkgroup, active or recent pane |
| `Enter` | switch to the highlighted talkgroup or talker |
| `m` | mute / unmute the highlighted talkgroup |
| `+` `-` `0` | output volume up / down / mute |
| `d` | audio device picker |
| `l` | log pane · `r` reconnect · `c` connect toggle · `?` help · `q` quit |

### Why is PTT a toggle?

Because a terminal delivers *characters*, not key events — there is no
key-release to detect, so true hold-to-talk is not possible without a global
input hook and a second permission prompt. Toggle is deterministic, works over
SSH and inside tmux, and `tx_timeout_sec` (default 120 s) plus `ESC` stop a
forgotten transmitter. For real push-to-talk hardware — a foot switch, a GPIO
pin — use the control FIFO:

```sh
echo "ptt on"  > ~/.local/state/svxconnect/ctl
echo "ptt off" > ~/.local/state/svxconnect/ctl
```

See [docs/PTT.md](docs/PTT.md).

### macOS: the microphone prompt names your terminal

macOS attributes a microphone request to the *responsible process*, which for a
command-line program is your terminal application. The prompt will say
"Terminal would like to access the microphone", not "SVXConnect". That is normal.
Microphone capture does not work over SSH — use `svxconnect --no-tx` there.
See [docs/TCC.md](docs/TCC.md).

## Roadmap

| | Milestone | Status |
|---|---|---|
| M0 | Skeleton, config parser, build system | **done** |
| M1 | Reflector client — mTLS, UDP crypto, heartbeats, reconnect (`--headless`) | **done** |
| M2 | Certificate enrolment (`--enroll`) | **done** |
| M3 | Audio device layer (`--list-devices`, `--audio-test`) | **done** |
| M4 | Receive audio — Opus decode, jitter buffer, loss concealment | **done** |
| M5 | Transmit audio, PTT via the control FIFO | **done** |
| M6 | Talkgroup manager — priority, lock, linger, idle, mute (26 tests) | **done** |
| M8 | Packaging — Homebrew formula, systemd unit, `DEPLOY.md` | **done** |
| M7 | ncurses interface | in progress |
| M9 | Polish — device picker modal, soak testing | |

Everything except the interface is verified against the live `be.svx.link`
reflector, including a transmit/receive round-trip through the parrot
talkgroup. `make test` runs 26 talkgroup-manager fixtures.

## Licence

MIT — see [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).

Copyright (c) 2026 Joeri Van Dooren, ON3URE.

## Headless and scripted use

`svxconnect --headless` runs without an interface, logging events to stdout,
and is what a systemd unit runs. Everything is controllable through a named
pipe:

```sh
echo "tg next"   > ~/.local/state/svxconnect/ctl
echo "lock on"   > ~/.local/state/svxconnect/ctl
echo "ptt on"    > ~/.local/state/svxconnect/ctl
echo "status"    > ~/.local/state/svxconnect/ctl
```

Full vocabulary in [docs/PTT.md](docs/PTT.md); service setup in
[DEPLOY.md](DEPLOY.md).

## Building and testing

```sh
make            # -> build/svxconnect
make test       # talkgroup manager fixtures
make asan       # AddressSanitizer + UndefinedBehaviorSanitizer build
```

Dependencies: OpenSSL 3, libopus, ncurses. Audio needs no development package
on either platform — [miniaudio](https://miniaud.io/) is vendored in
`third_party/` and loads the system audio libraries at runtime.
