# The macOS microphone permission

**Short version: the prompt will name your terminal application, not
SVXConnect. Allow it. If you ever denied it, fix it in System Settings →
Privacy & Security → Microphone. Microphone capture does not work over SSH.**

## Why the prompt says "Terminal"

macOS gates microphone access through TCC (Transparency, Consent and Control).
TCC attributes a request to the **responsible process** — for a program you
launched from a shell, that is the application that owns the session, not the
program itself. So the dialog reads:

> "Terminal" would like to access the microphone.

or "iTerm", "Ghostty", "WezTerm", "Code" if you are in the VS Code integrated
terminal, and so on. SVXConnect embeds a usage description
(`NSMicrophoneUsageDescription`) into its binary so the dialog has a sensible
explanation attached, but it cannot change whose name is on it.

The consequence worth knowing: once you allow it, the grant is stored against
your **terminal application**, so any other program you run from that terminal
can also use the microphone. That is how macOS works for command-line tools;
it is not something SVXConnect chooses.

## The silent failure mode

This is the one to watch for. If your terminal application was **previously
denied** microphone access — possibly months ago, by some unrelated program —
then macOS does not prompt, does not return an error, and does not fail to open
the device. CoreAudio reports success and then delivers **buffers of perfect
digital silence, forever**.

Without a check, the experience is: you key up, the reflector shows you
transmitting, the microphone meter sits at zero, and nobody hears a thing.

SVXConnect watches for exactly this. If the first 400 ms after you key up are
bit-exact zeros across every sample — which a real microphone never produces,
there is always at least a least-significant-bit of noise — it raises:

```
!! MIC BLOCKED — macOS delivered 400 ms of digital silence.
   Grant Microphone access to your terminal app (Privacy & Security > Microphone),
   then restart svxconnect.  Press 'x' to dismiss.
```

## Fixing it

Open **System Settings → Privacy & Security → Microphone** and enable your
terminal application. Or from a shell:

```sh
open "x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone"
```

To make macOS ask you again from scratch:

```sh
tccutil reset Microphone com.apple.Terminal      # or com.googlecode.iterm2, etc.
```

Then restart `svxconnect`.

## SSH

There is no responsible GUI process over SSH and therefore no way to present a
consent dialog. Microphone capture on macOS over SSH does not work and cannot
be made to work. Receiving, monitoring and talkgroup switching are all fine —
run:

```sh
svxconnect --no-tx
```

which is a first-class receive-only mode. The status bar shows `RX ONLY` so
there is no ambiguity about whether you are able to transmit.

## tmux and screen

Under tmux, the responsible process is the tmux **server**, which inherited its
context from whichever terminal first started it. Grants can land somewhere
surprising and survive detaching. Run SVXConnect outside tmux the first time so
the prompt is attributed to the terminal you are actually looking at; after
that it works fine inside.

## A note on code signing

SVXConnect ships ad-hoc signed. That is deliberate:

- **Unsigned or ad-hoc signed** — TCC falls back to the responsible parent
  process, which is the behaviour described above. This is what we ship.
- **Hardened runtime without the audio entitlement** — the microphone is denied
  outright, not merely attributed elsewhere. If you build from source, never
  pass `codesign --options runtime` unless you also pass
  `com.apple.security.device.audio-input`.

Homebrew ad-hoc re-signs binaries during relocation on Apple Silicon anyway, so
a Developer ID signature would not survive a bottle install even if we had one.

## Linux

None of this applies. PipeWire and ALSA impose no permission model outside of
Flatpak, and SVXConnect is not distributed as a Flatpak. The microphone just
works.
