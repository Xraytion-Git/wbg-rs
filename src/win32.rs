//! Foreground window tracking (user32/kernel32 FFI).

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type HWND = *mut c_void;

#[link(name = "user32")]
extern "system" {
    fn GetForegroundWindow() -> HWND;
    fn GetWindowTextW(h: HWND, buf: *mut u16, max: i32) -> i32;
    fn GetWindowThreadProcessId(h: HWND, pid: *mut u32) -> u32;
    fn IsWindowVisible(h: HWND) -> i32;
    fn EnumWindows(cb: *mut c_void, lp: isize) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
    fn QueryFullProcessImageNameW(h: HANDLE, flags: u32, buf: *mut u16, len: *mut u32) -> i32;
    fn CloseHandle(h: HANDLE) -> i32;
}

#[derive(Clone, Debug, Default)]
pub struct Foreground {
    pub exe_path: String,
    pub exe_name: String,
    pub dir: String,
    pub title: String,
}

#[derive(Clone, Debug, Default)]
pub struct WindowInfo {
    pub pid: u64,
    pub title: String,
    pub path: String,
    pub name: String,
}

/// Visible top-level windows with titles (for Wootility's "link a window").
pub fn visible_windows() -> Vec<WindowInfo> {
    use std::sync::Mutex;
    static OUT: Mutex<Vec<WindowInfo>> = Mutex::new(Vec::new());
    unsafe extern "system" fn cb(hwnd: HWND, _lp: isize) -> i32 {
        if IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let mut title = [0u16; 512];
        let n = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
        if n <= 0 {
            return 1;
        }
        let title = String::from_utf16_lossy(&title[..n as usize]);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        let (path, name) = process_path(pid);
        if let Ok(mut out) = OUT.lock() {
            out.push(WindowInfo {
                pid: u64::from(pid),
                title,
                path,
                name,
            });
        }
        1
    }
    if let Ok(mut out) = OUT.lock() {
        out.clear();
    }
    unsafe {
        EnumWindows(cb as *mut c_void, 0);
    }
    OUT.lock().map(|o| o.clone()).unwrap_or_default()
}

pub fn process_path(pid: u32) -> (String, String) {
    unsafe {
        let proc = OpenProcess(0x1000, 0, pid);
        if proc.is_null() {
            return (String::new(), String::new());
        }
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        let mut path = String::new();
        if QueryFullProcessImageNameW(proc, 0, buf.as_mut_ptr(), &mut len) != 0 {
            path = String::from_utf16_lossy(&buf[..len as usize]);
        }
        CloseHandle(proc);
        let name = path.rsplit('\\').next().unwrap_or("").to_string();
        (path, name)
    }
}

/// Cached foreground-window tracker: avoids re-querying the process path on
/// every poll (OpenProcess + QueryFullProcessImageName are the expensive part;
/// GetForegroundWindow + GetWindowTextW are cheap).  Process path is re-queried
/// only when HWND or PID changes; the window title is always fresh (needed for
/// `window_title` matching rules).
pub struct ForegroundTracker {
    last_hwnd: HWND,
    last_pid: u32,
    cached_path: String,
    cached_name: String,
    cached_dir: String,
}

impl ForegroundTracker {
    pub fn new() -> Self {
        Self {
            last_hwnd: std::ptr::null_mut(),
            last_pid: 0,
            cached_path: String::new(),
            cached_name: String::new(),
            cached_dir: String::new(),
        }
    }

    /// Returns the current foreground window, or None if none / inaccessible.
    pub fn poll(&mut self) -> Option<Foreground> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_null() {
                return None;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);

            // Title is cheap — always re-read for window_title rules.
            let mut title = [0u16; 512];
            let n = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
            let title = String::from_utf16_lossy(&title[..n.max(0) as usize]);

            // Process path is expensive — cache by (HWND, PID).
            if hwnd != self.last_hwnd || pid != self.last_pid {
                let (path, name) = process_path(pid);
                if !path.is_empty() {
                    self.last_hwnd = hwnd;
                    self.last_pid = pid;
                    self.cached_dir = path
                        .rsplit_once('\\')
                        .map(|(d, _)| d.to_string())
                        .unwrap_or_default();
                    self.cached_path = path;
                    self.cached_name = name;
                } else {
                    // Don't cache failures (transient during process startup);
                    // force a retry on the next poll.
                    self.last_hwnd = std::ptr::null_mut();
                    self.last_pid = 0;
                    self.cached_path.clear();
                    self.cached_name.clear();
                    self.cached_dir.clear();
                }
            }

            Some(Foreground {
                exe_path: self.cached_path.clone(),
                exe_name: self.cached_name.clone(),
                dir: self.cached_dir.clone(),
                title,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Event-driven foreground watcher (SetWinEventHook)
// ---------------------------------------------------------------------------

type HWINEVENTHOOK = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct POINT {
    x: i32,
    y: i32,
}

#[repr(C)]
struct MSG {
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: POINT,
}

const EVENT_SYSTEM_FOREGROUND: u32 = 0x0003;
const WINEVENT_OUTOFCONTEXT: u32 = 0x0000;

#[link(name = "user32")]
extern "system" {
    fn SetWinEventHook(
        event_min: u32,
        event_max: u32,
        hmod: *mut c_void,
        proc_: Option<unsafe extern "system" fn(HWINEVENTHOOK, u32, HWND, i32, i32, u32, u32)>,
        id_process: u32,
        id_thread: u32,
        flags: u32,
    ) -> HWINEVENTHOOK;
    fn UnhookWinEvent(h: HWINEVENTHOOK) -> i32;
    fn GetMessageW(msg: *mut MSG, hwnd: HWND, min: u32, max: u32) -> i32;
    fn TranslateMessage(msg: *const MSG) -> i32;
    fn DispatchMessageW(msg: *const MSG) -> isize;
}

static FG_TX: std::sync::OnceLock<std::sync::mpsc::Sender<()>> = std::sync::OnceLock::new();

unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    _event: u32,
    _hwnd: HWND,
    _obj: i32,
    _child: i32,
    _thread: u32,
    _time: u32,
) {
    if let Some(tx) = FG_TX.get() {
        let _ = tx.send(());
    }
}

/// Start an event-driven foreground watcher.  Returns a Receiver<()> that
/// yields one message per EVENT_SYSTEM_FOREGROUND.  Zero CPU when idle — the
/// message-pump thread blocks in GetMessageW until Windows signals a change.
pub fn start_foreground_watcher() -> std::sync::mpsc::Receiver<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let _ = FG_TX.set(tx);
    std::thread::spawn(move || unsafe {
        let hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            std::ptr::null_mut(),
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        );
        if hook.is_null() {
            return;
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        UnhookWinEvent(hook);
    });
    rx
}
