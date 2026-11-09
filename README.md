# wbg-rs

Windows replacement for the Wooting Background Service, fixing app-linked
profile switching that dies for the whole session when a game anti-cheat
(NARAKA: BLADEPOINT / NeacSafe64) is running.

## What it fixes

The stock service treats a transient HID read error on the keyboard's FF55
control interface (`ERROR_DEVICE_NOT_CONNECTED 0x48F`, caused by anti-cheat
handling of the keyboard USB stack) as a permanent device removal: it ends the
device task and passively waits for the device to reappear — observed switching
outages of up to 38 minutes per game session. This service instead:

- reopens the FF55 control interface within ~1 second of a handle failure,
- re-applies the pending profile switch after reconnecting (with firmware
  readback verification),
- preserves the user's onboard baseline profile and never overrides manual
  Mode/Cycle key presses.

## Feature surface

- FF55 control protocol: profile enumeration/metadata, activate,
  select-linked (all with readback verification)
- Foreground app matching against keyboard-resident linked-app rules
  (process name / directory / full path / window title) plus the Steam app
  inventory shared with the stock service
- Wootility compatibility API (gRPC-web over HTTP on 127.0.0.1:50052):
  Heartbeat, auto-start management, linkable apps, open windows, data sources
- Fully silent background operation (no windows, no console flashes)

## Build

Requires a Rust toolchain for Windows:

```
cargo build --release
```

## Install

Stop the official Wooting Background Service, then place the binary at
`wooting-bg-service.exe` in its install directory. Uninstall by removing the
binary; no other system state is required. Auto-start is managed through the
standard `HKCU\...\Run` key (also toggled from Wootility).

## Credits

Protocol framing and profile semantics were reverse-engineered and
cross-validated against two MIT-licensed reference implementations:

- [logixism/open-wbg-service](https://github.com/logixism/open-wbg-service)
- [apfelgriebsch/KeyProfileBridge](https://github.com/apfelgriebsch/KeyProfileBridge)

The profile-transition state machine (`src/link.rs`) is adapted from
open-wbg-service with its MIT attribution retained.
