# Arche Defender

A small desktop GUI that sweeps the usual persistence and tampering spots and tells you what changed since last time.

One file, no dependencies, no root needed. It is read-only: it never kills, deletes or changes anything.

Built on Nobara (Fedora, KDE Plasma); needs Python 3 with tkinter.

## Run

Run `./arche-defender.py`, or add it to the app menu:

```sh
printf '[Desktop Entry]\nType=Application\nName=Arche Defender\nExec=%s/arche-defender.py\nIcon=security-high\nCategories=System;Security;\nStartupWMClass=Arche-defender\n' "$PWD" > ~/.local/share/applications/arche-defender.desktop
```

On the first run everything is green because there is no baseline. Review the lists, click **Accept as baseline**, and later scans highlight only what is new.

## What it checks

| Check | Red alert | Tracked against baseline |
|---|---|---|
| Security posture | firewalld not active, no package updates in 14 days | SELinux mode, Secure Boot |
| Running programs | running from /tmp, /var/tmp, /dev/shm, memfd or Downloads | executables not from an RPM (Flatpak, Steam, home dir), deleted binaries still running |
| Network listeners | | processes listening beyond loopback |
| Startup entries | | XDG autostart, Plasma env/shutdown scripts, /etc/profile.d, shell rc and environment.d lines |
| Scheduled tasks | | systemd timers (system and user), crontabs, cron.* scripts |
| Services | | systemd services whose unit file is outside /usr (added by hand) |
| Hijack points | /etc/ld.so.preload, LD_PRELOAD in environment files, sudo/ssh/su shadowed in a user bin dir or aliased in an rc file, pam_exec | udev rules that RUN a command |
| Network settings | | hosts entries, DNS servers, proxy (env and KDE) |
| Remote access and accounts | a second uid-0 account | sshd, RDP, VNC, RustDesk, AnyDesk, TeamViewer, Sunshine running; SSH authorized keys; Samba and NFS shares; login accounts; wheel members |
| Browser extensions | | Chrome, Chromium, Edge, Brave, Vivaldi, Helium (native and Flatpak) and Firefox extensions, native messaging hosts |
| Kernel modules | | out-of-tree or unsigned modules (NVIDIA is both on a stock install) |

Without root it cannot see other users' processes (root daemons' executables and listener owners), `/root`, sudoers or Samba usershares.

## Notes

- `baseline.json` is written beside the script and lists what is on your machine. It is git-ignored and mode 600; do not publish it.
- `./arche-defender.py --selftest` runs every check headless and prints the counts.
- It is a tripwire, not an antivirus: it shows changes, and you decide what they mean.
