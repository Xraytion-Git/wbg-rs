//! wbg-rs: drop-in replacement for wooting-bg-service with the Naraka fix.
//! The stock service dies when the anti-cheat resets the keyboard's USB
//! (hid_read error 0x48F "device not connected") and waits passively for the
//! device to reappear, so app-linked profile switching is dead for the whole
//! game session. Here: shared open + 1s reconnect + re-plan/re-apply pending
//! transitions on reconnect (LinkState keeps the return profile).

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
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let mut last = "no matching response".to_string();
    let mut buf = vec![0u8; 4096];
    loop {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
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

struct Session {
    dev: hid::Dev,
    rules: matchers::Rules,
    state: LinkState,
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

fn main() {
    spawn_logger();
    log(&format!("wbg-rs start pid={}", std::process::id()));
    std::thread::spawn(api::serve);
    let mut session: Option<Session> = None;
    let mut last_desired: Option<ProfileId> = None;
    let mut tick: u64 = 0;
    loop {
        if session.is_none() {
            match try_open() {
                Ok(s) => {
                    let had_pending = last_desired.is_some();
                    session = Some(s);
                    if had_pending {
                        log("reconnected with pending target - will re-apply");
                    }
                }
                Err(e) => {
                    log(&format!("waiting for device: {e}"));
                }
            }
        }
        if let Some(s) = session.as_mut() {
            let fg = win32::foreground();
            let desired = fg.as_ref().and_then(|f| s.rules.desired(f));
            tick += 1;
            if desired != last_desired || tick % 20 == 0 {
                log(&format!(
                    "hb fg={} desired={:?} ({})",
                    fg.as_ref().map(|f| f.exe_name.as_str()).unwrap_or("?"),
                    desired,
                    desired
                        .map(|d| s.rules.profile_name(d))
                        .unwrap_or_default()
                ));
                last_desired = desired;
            }
            match current_profile(&mut s.dev) {
                Ok(current) => {
                    if let Some(t) = s.state.plan(current, desired) {
                        let mut op = Ok(());
                        if let Some(sel) = t.selection {
                            op = select_linked(&mut s.dev, sel);
                        }
                        if op.is_ok() {
                            if let Some(a) = t.activate {
                                op = activate(&mut s.dev, a);
                            }
                        }
                        match op {
                            Ok(()) => {
                                s.state = t.next;
                                log(&format!("transition applied desired={desired:?}"));
                            }
                            Err(e) => {
                                log(&format!("transition FAILED ({e}) - dropping device, will retry"));
                                session = None;
                            }
                        }
                    }
                }
                Err(e) => {
                    log(&format!("device lost: {e}"));
                    session = None;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(750));
    }
}
