# Kill switch — scope for v1.4.0

## TL;DR

- **Linux** — kill switch enforced. Default `-kill-switch=true`. Tested.
- **Windows** — kill switch code shipped but **default `-kill-switch=false`** in v1.4.0. Sprint 9 will land the elevation shim that makes it safe to flip on by default. Enable it early with `-kill-switch=true` at your own risk (elevation guard will error out cleanly if the process was not launched at HIGH integrity).
- **macOS / *BSD** — unsupported; kill switch always no-ops.

## Why the Windows asymmetry

Kill switch on Windows uses `Set-NetFirewallProfile -DefaultOutboundAction Block` plus a group of allow-list rules for the tunnel + LAN + Arena control plane. That call requires **HIGH integrity level**, not just Administrator group membership.

install.ps1 already elevates its own PowerShell session (checks `IsInRole(Administrator)` and throws otherwise), but the `Start-Process arena-byoc.exe` it uses to spawn the daemon inherits **MEDIUM integrity** by default. `Set-NetFirewallProfile` from a MEDIUM child fails **silently** — no error return, no exception, just no effect on the profile. The verify step we added in `killswitch_windows.go` catches this and refuses to claim armed, but it also means the switch would refuse to arm on the default install flow.

The fix belongs one layer up (either an embedded `requestedExecutionLevel level="requireAdministrator"` manifest, `Start-Process -Verb RunAs` in install.ps1, or the "real production" pattern — a Windows Service running as `LocalSystem`). Each has trade-offs we didn't want to hard-decide in the v1.4.0 window:

- **Manifest** — one-off UAC prompt per launch; annoying for a background daemon.
- **`-Verb RunAs`** — silent when the caller is already elevated, but changes install.ps1 semantics.
- **Windows Service** — the WireGuard-for-Windows / NordVPN / Tailscale pattern. Zero UAC friction after install, but adds a second binary, an IPC protocol, code-signing pressure, an auto-updater surface, and support burden.

The RTaaS side already treats the `killSwitchArmed` heartbeat flag as a chip-only decoration (`PROTECTED` when true, `TUNNEL_UP` when false). Shipping Windows with `armed=false` degrades gracefully — the chip stays honest, no fake security promises to the student.

## User contract

- If you're a Linux student, nothing changes vs the v1.4.0 spec: run `arena-byoc`, chip flips to `PROTECTED`.
- If you're a Windows student, the tunnel comes up (winipcfg-driven — v1.3.0 parity restored) and the chip shows `TUNNEL_UP`. You are **not** kill-switched. If your tunnel drops mid-session, traffic falls back to your local ISP → the scenario target sees your real IP until you reconnect.
- If you explicitly pass `-kill-switch=true` on Windows: the switch's elevation guard runs the flip, verifies the profile, and hard-errors if the process is MEDIUM integrity. No silent partial arming.

## Sprint 9 target

Pick one of the three fixes above (leaning toward `-Verb RunAs` in install.ps1 as the smallest change; leaning toward a real Windows Service as the eventual correct answer). Sprint 9 doc will call the shot with concrete cost estimates.

Until then, "kill switch on Windows" is an opt-in developer flag, not a supported user feature.
