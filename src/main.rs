//! wbg-rs: drop-in replacement for wooting-bg-service with the Naraka fix.
//! The stock service dies when the anti-cheat resets the keyboard's USB
//! (hid_read error 0x48F "device not connected") and waits passively for the
//! device to reappear, so app-linked profile switching is dead for the whole
//! game session. Here: shared open + fast handle reconnect + re-plan/re-apply
//! pending transitions on reconnect (LinkState keeps the return profile).
//!
//! Performance design (vs the 750 ms poll-loop original):
//! - Foreground polled at 80 ms with cached process path (re-query only on
//!   HWND/PID change) — switching detection latency 0-80 ms instead of 0-750 ms.
//! - Device I/O only when the desired profile actually changes (or after
//!   reconnect) — no per-tick firmware reads.
//! - Handle-level reconnect: reopen by known path in ~1 ms, preserve Rules +
//!   LinkState. Full re-enumeration only when fast reconnect fails.

#![windows_subsystem = "windows"]

mod api;
mod ff55;
mod hid;
mod link;
mod matchers;
mod win32;

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::mpsc::{Sender, channel};
use std::time::{Duration, Instant};

use ff55::*;
use link::LinkState;

// Logging runs on its own thread: a stalled disk write must never freeze the
// switching loop (this box has intermittent multi-second I/O stalls).
static LOGTX: OnceLock<Sender<String>> = OnceLock::new();

fn log(msg: &str) {
    if let Some(tx) = LOGTX.get() {
        let _ = tx.send(format!("{} {}", civil_ts(), msg));
    }
}

fn spawn_logger() {
    let (tx, rx) = channel::<String>();
    let _ = LOGTX.set(tx);
    std::thread::spawn(move || {
        let p = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("wbg-rs.log")))
            .unwrap_or_else(|| std::path::PathBuf::from("wbg-rs.log"));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
            while let Ok(line) = rx.recv() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
    });
}

#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millis: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLocalTime(st: *mut SystemTime);
}

fn civil_ts() -> String {
    let mut st = SystemTime::default();
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.year, st.month, st.day, st.hour, st.minute, st.second
    )
}

fn query(dev: &mut hid::Dev, command: u8, param: u32) -> Result<Vec<u8>, String> {
    dev.drain();
    dev.set_feature(&command_frame(command, param))
        .map_err(|e| format!("send 0x{command:02x}: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut last = "no matching response".to_string();
    let mut buf = vec![0u8; 4096];
    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return Err(format!("cmd 0x{command:02x} timeout: {last}"));
        }
        let ms = remain.as_millis().min(u32::MAX as u128) as u32;
        let n = dev
            .read_timeout(&mut buf, ms)
            .map_err(|e| format!("cmd 0x{command:02x} read: {e}"))?;
        if n == 0 {
            continue;
        }
        match parse_reply(&buf[..n], command) {
            Ok(r) if r.status == 0x88 => return Ok(r.body.to_vec()),
            Ok(r) => return Err(format!("cmd 0x{command:02x} fw status 0x{:02x}", r.status)),
            Err(e) => last = e,
        }
    }
}

fn read_profiles(dev: &mut hid::Dev) -> Result<Vec<Profile>, String> {
    let mut profiles = Vec::new();
    for ns in [0u8, 1] {
        let count = query(dev, CMD_COUNT, u32::from(ns))
            .and_then(|b| b.first().copied().ok_or("count reply empty".into()))?;
        for idx in 0..count {
            let id = ProfileId {
                namespace: ns,
                index: idx,
            };
            let meta = query(dev, CMD_METADATA, id.parameter())?;
            let name = metadata_name(&meta)?;
            let mut apps = Vec::new();
            if ns == 1 {
                let ac = query(dev, CMD_APP_COUNT, id.parameter())
                    .and_then(|b| b.first().copied().ok_or("app count empty".into()))?;
                for a in 0..ac.min(8) {
                    let body = query(dev, CMD_APP, id.parameter() | (u32::from(a) << 16))?;
                    apps.push(parse_app(&body)?);
                }
            }
            profiles.push(Profile { id, name, apps });
        }
    }
    Ok(profiles)
}

fn current_profile(dev: &mut hid::Dev) -> Result<ProfileId, String> {
    let body = query(dev, CMD_CURRENT, 0)?;
    if body.is_empty() {
        return Err("current-profile reply empty".into());
    }
    Ok(ProfileId {
        index: body[0],
        namespace: body.get(1).copied().unwrap_or(0),
    })
}

fn linked_profile(dev: &mut hid::Dev) -> Result<Option<ProfileId>, String> {
    let body = query(dev, CMD_LINKED, 0)?;
    match body.as_slice() {
        [] => Ok(None),
        [index, namespace] => Ok(Some(ProfileId {
            namespace: *namespace,
            index: *index,
        })),
        _ => Err(format!("linked-profile reply len {}", body.len())),
    }
}

fn select_linked(dev: &mut hid::Dev, profile: Option<ProfileId>) -> Result<(), String> {
    let param = match profile {
        Some(id) => {
            if id.namespace != 1 {
                return Err(format!("select_linked requires ns 1, got {}", id.namespace));
            }
            id.parameter()
        }
        None => 0xffff,
    };
    query(dev, CMD_SELECT_LINKED, param)?;
    let actual = linked_profile(dev)?;
    if actual != profile {
        return Err(format!("select_linked not applied: want {profile:?} got {actual:?}"));
    }
    Ok(())
}

fn activate(dev: &mut hid::Dev, id: ProfileId) -> Result<(), String> {
    query(dev, CMD_ACTIVATE, id.parameter())?;
    let actual = current_profile(dev)?;
    if actual != id {
        return Err(format!("activate not applied: want {id:?} got {actual:?}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Session: one live device handle + its rules and link state.
// ---------------------------------------------------------------------------

struct Session {
    dev: hid::Dev,
    rules: matchers::Rules,
    state: LinkState,
}

impl Session {
    /// Fast handle reconnect: reopen by known path, verify with a probe read.
    /// Preserves `rules` and `state` across the handle swap — no re-enumeration,
    /// no profile re-read.  Returns the device's actual current profile so the
    /// caller can re-sync.
    fn reconnect(&mut self) -> Result<ProfileId, String> {
        let path = self.dev.path.clone();
        let mut fresh = hid::Dev::open_path(&path)
            .map_err(|e| format!("reopen {}: {e}", path))?;
        let current = current_profile(&mut fresh)
            .map_err(|e| format!("probe after reopen: {e}"))?;
        self.dev = fresh; // old handle dropped (closed) here
        log(&format!("handle reconnected {path}, current={current:?}"));
        Ok(current)
    }
}

fn try_open() -> Result<Session, String> {
    let cands = hid::enumerate_all();
    if cands.is_empty() {
        return Err("no Wooting FF55 interface".into());
    }
    for cand in &cands {
        let mut dev = hid::Dev::open(cand).map_err(|e| format!("open {}: {e}", cand.path))?;
        match read_profiles(&mut dev) {
            Ok(profiles) => {
                let cur = current_profile(&mut dev)?;
                let state = LinkState::new(cur, 0);
                let steam = matchers::Rules::load_inventory();
                log(&format!(
                    "device up {} profiles={} steam_apps={} current={:?}",
                    cand.path,
                    profiles.len(),
                    steam.len(),
                    cur
                ));
                for p in &profiles {
                    log(&format!(
                        "  profile {}/{} {:?} apps={}",
                        p.id.namespace,
                        p.id.index,
                        p.name,
                        p.apps
                            .iter()
                            .map(|a| format!(
                                "[{:?}|{}]",
                                a.name,
                                a.filters
                                    .iter()
                                    .map(|f| format!("{}={:?}", f.kind, f.value))
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                }
                return Ok(Session {
                    dev,
                    rules: matchers::Rules { profiles, steam },
                    state,
                });
            }
            Err(e) => {
                log(&format!("skip {}: {e}", cand.path));
            }
        }
    }
    Err("no usable control interface".into())
}

fn execute_transition(dev: &mut hid::Dev, t: &link::Transition) -> Result<(), String> {
    let mut op = Ok(());
    if let Some(sel) = t.selection {
        op = select_linked(dev, sel);
    }
    if op.is_ok() {
        if let Some(a) = t.activate {
            op = activate(dev, a);
        }
    }
    op
}

// ---------------------------------------------------------------------------
// Main event loop
// ---------------------------------------------------------------------------

fn main() {
    spawn_logger();
    log(&format!("wbg-rs start pid={}", std::process::id()));
    std::thread::spawn(api::serve);

    let mut tracker = win32::ForegroundTracker::new();
    let mut session: Option<Session> = None;
    // LinkState survives across full reconnects so that a pending target and
    // the user's baseline are never lost when the device has to be re-opened.
    let mut saved_link: Option<LinkState> = None;
    let mut desired: Option<ProfileId> = None;
    let mut needs_sync = true;
    let mut fg_none_since: Option<Instant> = None;
    let mut return_desired: Option<ProfileId> = None;
    let mut last_hb = Instant::now();
    let mut backoff = Duration::from_millis(100);

    loop {
        // === Ensure device session ===
        if session.is_none() {
            match try_open() {
                Ok(mut s) => {
                    if let Some(prev) = saved_link.take() {
                        s.state = prev;
                    }
                    session = Some(s);
                    needs_sync = true;
                    backoff = Duration::from_millis(100);
                }
                Err(e) => {
                    log(&format!("waiting for device: {e}"));
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        }

        // === Foreground detection (cheap; process path is cached) ===
        let fg = tracker.poll();
        let raw_desired = session
            .as_ref()
            .and_then(|s| fg.as_ref().and_then(|f| s.rules.desired(f)));

        // When GetForegroundWindow returns null (brief flicker during window
        // switches), keep the previous desired instead of dropping to baseline.
        let new_desired = match (&fg, &raw_desired) {
            (None, _) => desired, // transient null foreground — keep current
            (Some(_), _) => raw_desired,
        };

        // Debounce only transient fg=None flickers; switch immediately when
        // a real non-linked window is in the foreground.
        if raw_desired.is_some() {
            fg_none_since = None;
            return_desired = raw_desired;
        } else if desired.is_some() {
            if fg.is_none() {
                // Transient null foreground during window switch — debounce 300 ms.
                if fg_none_since.is_none() {
                    fg_none_since = Some(Instant::now());
                }
                if fg_none_since.unwrap().elapsed() < Duration::from_millis(50) {
                    return_desired = desired;
                } else {
                    return_desired = None;
                }
            } else {
                // Real non-linked window in foreground — return to baseline now.
                fg_none_since = None;
                return_desired = None;
            }
        } else {
            fg_none_since = None;
            return_desired = None;
        }

        // === Diagnostic: log when desired changes or on every heartbeat ===
        if return_desired != desired {
            log(&format!(
                "desired changed: {:?} -> {:?}  fg={:?}",
                desired,
                return_desired,
                fg.as_ref().map(|f| format!(
                    "exe={} path={} dir={} title={}",
                    f.exe_name, f.exe_path, f.dir, f.title
                ))
            ));
        }

        // === Switch profiles when the desired target changes (or on resync) ===
        let mut needs_drop = false;
        if return_desired != desired || needs_sync {
            desired = return_desired;
            needs_sync = false;
            let s = session.as_mut().unwrap();
            match current_profile(&mut s.dev) {
                Ok(current) => {
                    if let Some(t) = s.state.plan(current, desired) {
                        match execute_transition(&mut s.dev, &t) {
                            Ok(()) => {
                                s.state = t.next;
                                log("transition applied");
                            }
                            Err(e) => {
                                log(&format!("transition failed ({e}), reconnecting"));
                                match s.reconnect() {
                                    Ok(_) => needs_sync = true,
                                    Err(e2) => {
                                        log(&format!("fast reconnect failed: {e2}"));
                                        needs_drop = true;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    log(&format!("device lost ({e}), reconnecting"));
                    match s.reconnect() {
                        Ok(_) => needs_sync = true,
                        Err(e2) => {
                            log(&format!("fast reconnect failed: {e2}"));
                            needs_drop = true;
                        }
                    }
                }
            }
        }

        // === Drop session (preserving LinkState) when fast reconnect failed ===
        if needs_drop {
            if let Some(s) = session.as_ref() {
                saved_link = Some(s.state.clone());
            }
            session = None;
            needs_sync = true;
        }

        // === Heartbeat ===
        if last_hb.elapsed() > Duration::from_secs(5) {
            last_hb = Instant::now();
            let fg_detail = fg.as_ref().map(|f| format!(
                "exe={} path={} dir={} title={}",
                f.exe_name, f.exe_path, f.dir, f.title
            )).unwrap_or("None".into());
            let d_name = desired
                .and_then(|d| session.as_ref().map(|s| s.rules.profile_name(d)))
                .unwrap_or_default();
            let st = session.as_ref().map(|s| format!(
                "target={:?} baseline={:?}",
                s.state.target, s.state.baseline
            )).unwrap_or("no session".into());
            log(&format!("hb fg={fg_detail} desired={d_name}({desired:?}) {st}"));
        }

        std::thread::sleep(Duration::from_millis(80));
    }
}
