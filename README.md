# Arche Defender

A small Windows GUI that sweeps the usual persistence and tampering spots and tells you what changed since last time.

One PowerShell file, no dependencies, no admin needed. It is read-only: it never kills, deletes or changes anything.

## Run

Double-click `ArcheDefender.cmd`.

On the first run everything is green because there is no baseline. Review the lists, click **Accept as baseline**, and later scans highlight only what is new.

## What it checks

| Check | Red alert | Tracked against baseline |
|---|---|---|
| Defender | protection off, stale signatures, recent detections | exclusions (elevated only) |
| Running programs | running from Temp, Downloads or Public | unsigned executables |
| Network listeners | | processes listening beyond loopback |
| Startup entries | | Run keys and Startup folders |
| Scheduled tasks | | non-Microsoft tasks that run a program |
| Services | | running services outside `\Windows\` |
| Hijack points | Winlogon, AppInit_DLLs, IFEO debuggers, WMI consumers | |
| Network settings | | hosts entries, DNS servers, proxy |
| Remote access and accounts | | RDP, sshd, WinRM, SSH keys, shares, enabled accounts |
| Browser extensions | | Chrome, Edge and Brave extensions, native messaging hosts |
| Drivers | unsigned third-party drivers | signed third-party drivers |

## Notes

- `baseline.json` is written beside the script and lists what is on your machine. It is git-ignored; do not publish it.
- `ArcheDefender.ps1 -SelfTest` runs every check headless and prints the counts.
- It is a tripwire, not an antivirus: it shows changes, and you decide what they mean.
