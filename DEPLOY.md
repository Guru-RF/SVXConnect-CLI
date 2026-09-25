# Running SVXConnect-CLI as a service

This covers the **headless** mode — an unattended node that monitors talkgroups
and (optionally) transmits under script control. The interactive ncurses
interface is not a service: it wants a terminal.

If you just want to use SVXConnect at a keyboard, you do not need any of this.
See [README.md](README.md).

## Build and install

```sh
sudo apt install build-essential pkg-config libncurses-dev libssl-dev libopus-dev
git clone https://github.com/Guru-RF/SVXConnect-CLI
cd SVXConnect-CLI
make
sudo make install          # -> /usr/local/bin/svxconnect
```

There is no audio development package in that list, and that is deliberate: the
device layer loads `libasound.so.2` or `libpulse.so.0` at runtime if they are
present. On Pi OS Bookworm and Ubuntu 22.04+ the PipeWire server is already
there via `pipewire-pulse`; on older or minimal systems `libasound2` is enough.

## A dedicated user

```sh
sudo useradd --system --home-dir /var/lib/svxconnect --create-home \
             --shell /usr/sbin/nologin svxconnect
sudo usermod -aG audio svxconnect
```

The `audio` group is what gives the service access to `/dev/snd`.

## Configuration

One file per instance, named after the instance:

```sh
sudo svxconnect --init-config -c /etc/svxconnect/be.conf
sudo $EDITOR /etc/svxconnect/be.conf
```

`--init-config` creates the directory, writes the fully commented example and
asks for the callsign, email and reflector. Add `--set key=value` for any other
key, which is handy when provisioning several instances from a script.

Point the writable paths at the service's state directory:

```ini
pki_dir  = /var/lib/svxconnect/pki
ctl_fifo = /var/lib/svxconnect/ctl
log_file =                                # empty: log to the journal instead
```

Then lock it down. The config names a callsign and the PKI directory holds a
private key, so neither should be world-readable:

```sh
sudo chown -R svxconnect:svxconnect /etc/svxconnect /var/lib/svxconnect
sudo chmod 750 /etc/svxconnect
sudo chmod 640 /etc/svxconnect/*.conf
sudo chmod 700 /var/lib/svxconnect/pki
```

`svxconnect` writes its own key `0600` and never loosens it, but the enclosing
directory is yours to get right.

## Enrol the certificate

Enrolment waits for a human — the reflector sysop has to approve the request —
so do it by hand, as the service user, before enabling the unit:

```sh
sudo -u svxconnect svxconnect --enroll -c /etc/svxconnect/be.conf
```

It retries every 30 s and is safe to interrupt; the key and CSR stay on disk and
are reused, so running it again continues where it left off. Enrolment is done
when it prints `enrolled.` (or, run again later, `the reflector accepts it`) —
not merely when `/var/lib/svxconnect/pki/<CALLSIGN>.crt` exists: a certificate
the reflector has refused stays on disk while its replacement waits for the
sysop.

## Install the unit

```sh
sudo cp packaging/systemd/svxconnect@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now svxconnect@be
```

The `@be` suffix selects `/etc/svxconnect/be.conf`. Run several instances by
adding more config files — but give **each one its own callsign and its own
certificate**. Two nodes presenting the same certificate will knock each other
off the reflector, repeatedly, for as long as both are running.

```sh
systemctl status svxconnect@be
journalctl -u svxconnect@be -f
```

## Transmitting from a service

A headless node cannot press a key, so PTT goes through the control FIFO:

```sh
echo "ptt on"  > /var/lib/svxconnect/ctl
echo "ptt off" > /var/lib/svxconnect/ctl
```

The FIFO is created mode 0600 owned by the service user, so a script that
drives it must run as `svxconnect` (or as root). The full command vocabulary is
in [docs/PTT.md](docs/PTT.md).

If the node never transmits, add `--no-tx` to `ExecStart` and it will not open
the microphone at all.

### A foot switch on a Raspberry Pi GPIO

```sh
#!/bin/sh
# /usr/local/bin/svxconnect-footswitch — GPIO 17, active high.
# apt install gpiod
CTL=/var/lib/svxconnect/ctl
gpiomon -b -F "%e" gpiochip0 17 | while read -r edge; do
    case "$edge" in
        1) echo "ptt on"  > "$CTL" ;;
        0) echo "ptt off" > "$CTL" ;;
    esac
done
```

## Troubleshooting

**No audio.** `sudo -u svxconnect svxconnect --list-devices -c /etc/svxconnect/be.conf`.
If it lists nothing, the service user is not in the `audio` group, or PulseAudio
is running per-user and the system service cannot reach it — on a headless box
prefer plain ALSA and name the device explicitly with `output_device`.

**Connects then drops repeatedly.** Almost always two nodes sharing one
certificate. Check whether the same callsign is running elsewhere.

**`no certificate for <CALL>`.** Enrolment has not completed. Run `--enroll`
again as the service user and wait for the sysop.

**`the reflector refused our certificate`.** It looks valid here, but the
reflector turns it away — revoked or removed on its side, or one of the two
clocks is wrong. The service requests a new one with the same key by itself and
logs in once the sysop has signed it. To do the same by hand, stop the service
and run `--enroll` as the service user: it checks the certificate with the
reflector and, when it is refused, requests the replacement and waits for it.

**Nothing in the journal.** Confirm `log_file` is empty in the config; a
configured log file takes the output away from stdout and therefore away from
the journal.
