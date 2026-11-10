//! Raw Win32 HID layer (no C toolchain): registry device-class scan + hid.dll.
//! Opens interfaces with FILE_SHARE_READ|FILE_SHARE_WRITE so a coexisting
//! anti-cheat handle does not block us (Nexus finding); device-loss errors are
//! surfaced so the caller can reconnect fast.

use std::ffi::c_void;
use std::io;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
pub const INVALID_HANDLE: isize = -1;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x102;
pub const INFINITE: u32 = 0xffffffff;

pub type HANDLE = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub h_event: HANDLE,
}

#[repr(C)]
pub struct HIDD_ATTRIBUTES {
    pub size: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version_number: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HIDP_CAPS {
    pub usage: u16,
    pub usage_page: u16,
    pub input_report_byte_length: u16,
    pub output_report_byte_length: u16,
    pub feature_report_byte_length: u16,
    pub reserved: [u16; 17],
    pub number_link_collection_nodes: u32,
    pub number_input_button_caps: u32,
    pub number_input_value_caps: u32,
    pub number_input_data_indices: u32,
    pub number_output_button_caps: u32,
    pub number_output_value_caps: u32,
    pub number_output_data_indices: u32,
    pub number_feature_button_caps: u32,
    pub number_feature_value_caps: u32,
    pub number_feature_data_indices: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sec: *mut c_void,
        disp: u32,
        flags: u32,
        tmpl: HANDLE,
    ) -> HANDLE;
    fn ReadFile(
        h: HANDLE,
        buf: *mut u8,
        len: u32,
        read: *mut u32,
        ov: *mut OVERLAPPED,
    ) -> i32;
    fn WriteFile(h: HANDLE, buf: *const u8, len: u32, written: *mut u32, ov: *mut OVERLAPPED) -> i32;
    fn CloseHandle(h: HANDLE) -> i32;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn GetOverlappedResult(h: HANDLE, ov: *mut OVERLAPPED, n: *mut u32, wait: i32) -> i32;
    fn CancelIo(h: HANDLE) -> i32;
    fn CreateEventW(sec: *mut c_void, manual: i32, initial: i32, name: *const u16) -> HANDLE;
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> HANDLE;
    fn GetProcAddress(mod_: HANDLE, name: *const u8) -> *mut c_void;
}

// hid.dll has no import lib in the minimal mingw toolchain; load at runtime.
type FnGetAttributes = unsafe extern "system" fn(HANDLE, *mut HIDD_ATTRIBUTES) -> i32;
type FnGetPreparsed = unsafe extern "system" fn(HANDLE, *mut *mut c_void) -> i32;
type FnFreePreparsed = unsafe extern "system" fn(*mut c_void) -> i32;
type FnGetCaps = unsafe extern "system" fn(*mut c_void, *mut HIDP_CAPS) -> u32;
type FnSetFeature = unsafe extern "system" fn(HANDLE, *mut u8, u32) -> i32;

struct HidFns {
    get_attributes: FnGetAttributes,
    get_preparsed: FnGetPreparsed,
    free_preparsed: FnFreePreparsed,
    get_caps: FnGetCaps,
    set_feature: FnSetFeature,
}

static HID_FNS: std::sync::OnceLock<Option<HidFns>> = std::sync::OnceLock::new();

fn hid_fns() -> Option<&'static HidFns> {
    HID_FNS
        .get_or_init(|| unsafe {
            let name = wstr("hid.dll");
            let module = LoadLibraryW(name.as_ptr());
            if module.is_null() {
                return None;
            }
            let sym = |n: &str| {
                let c = n.bytes().chain(std::iter::once(0)).collect::<Vec<u8>>();
                GetProcAddress(module, c.as_ptr())
            };
            let f = |p: *mut c_void| if p.is_null() { None } else { Some(p) };
            Some(HidFns {
                get_attributes: std::mem::transmute(f(sym("HidD_GetAttributes"))?),
                get_preparsed: std::mem::transmute(f(sym("HidD_GetPreparsedData"))?),
                free_preparsed: std::mem::transmute(f(sym("HidD_FreePreparsedData"))?),
                get_caps: std::mem::transmute(f(sym("HidP_GetCaps"))?),
                set_feature: std::mem::transmute(f(sym("HidD_SetFeature"))?),
            })
        })
        .as_ref()
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(root: HANDLE, sub: *const u16, opts: u32, sam: u32, out: *mut HANDLE) -> i32;
    fn RegEnumKeyExW(
        key: HANDLE,
        idx: u32,
        name: *mut u16,
        len: *mut u32,
        res: *mut u32,
        cls: *mut u16,
        cls_len: *mut u32,
        ft: *mut u8,
    ) -> i32;
    fn RegQueryValueExW(
        key: HANDLE,
        name: *const u16,
        res: *mut u32,
        typ: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: HANDLE) -> i32;
}

pub const HKLM: isize = (0x8000_0002u32 as i32) as isize;
const KEY_READ: u32 = 0x20019;

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

/// HID interface description: device path + usage coordinates + report sizes.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub path: String,
    pub usage_page: u16,
    pub usage: u16,
    pub input_len: u16,
    pub feature_len: u16,
    pub product_id: u16,
}

fn open_raw(path: &str, overlapped: bool) -> Result<HANDLE, io::Error> {
    let name = wstr(path);
    let flags = if overlapped { FILE_FLAG_OVERLAPPED } else { 0 };
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if h as isize == INVALID_HANDLE || h.is_null() {
        return Err(last_error());
    }
    Ok(h)
}

fn caps_of(h: HANDLE) -> Option<(HIDP_CAPS, u16)> {
    let fns = hid_fns()?;
    unsafe {
        let mut attrs = HIDD_ATTRIBUTES {
            size: std::mem::size_of::<HIDD_ATTRIBUTES>() as u32,
            vendor_id: 0,
            product_id: 0,
            version_number: 0,
        };
        if (fns.get_attributes)(h, &mut attrs) == 0 {
            return None;
        }
        let mut prep: *mut c_void = std::ptr::null_mut();
        if (fns.get_preparsed)(h, &mut prep) == 0 {
            return None;
        }
        let mut caps = HIDP_CAPS {
            usage: 0,
            usage_page: 0,
            input_report_byte_length: 0,
            output_report_byte_length: 0,
            feature_report_byte_length: 0,
            reserved: [0; 17],
            number_link_collection_nodes: 0,
            number_input_button_caps: 0,
            number_input_value_caps: 0,
            number_input_data_indices: 0,
            number_output_button_caps: 0,
            number_output_value_caps: 0,
            number_output_data_indices: 0,
            number_feature_button_caps: 0,
            number_feature_value_caps: 0,
            number_feature_data_indices: 0,
        };
        let ok = (fns.get_caps)(prep, &mut caps);
        (fns.free_preparsed)(prep);
        if ok != 0x00110000 {
            // HIDP_STATUS_SUCCESS
            return None;
        }
        Some((caps, attrs.product_id))
    }
}

/// Enumerate HID interfaces GUID-agnostically: walk every DeviceClasses
/// {GUID} class and pick `##?#HID#...` interface instances, rebuilding the
/// `\\?\...` device path from the key name (this box has no SymbolicLink
/// values and registers HID under a non-standard class GUID).
pub fn enumerate(page: u16, usage: u16) -> Vec<Candidate> {
    let mut paths: Vec<String> = Vec::new();
    let classes = wstr(r"SYSTEM\CurrentControlSet\Control\DeviceClasses");
    let mut root: HANDLE = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKLM as HANDLE, classes.as_ptr(), 0, KEY_READ, &mut root) } != 0 {
        return out_empty();
    }
    let mut gidx = 0u32;
    loop {
        let mut gname = [0u16; 256];
        let mut gnlen = gname.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(root, gidx, gname.as_mut_ptr(), &mut gnlen, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if rc != 0 {
            break;
        }
        gidx += 1;
        let mut cls: HANDLE = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(root, gname.as_ptr(), 0, KEY_READ, &mut cls) } != 0 {
            continue;
        }
        let mut iidx = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut nlen = name.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(cls, iidx, name.as_mut_ptr(), &mut nlen, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            if rc != 0 {
                break;
            }
            iidx += 1;
            let sub = String::from_utf16_lossy(&name[..nlen as usize]);
            let low = sub.to_ascii_lowercase();
            if low.starts_with("##?#hid#") && low.contains("vid_31e3") {
                let path = format!(r"\\?\{}", &sub[4..]);
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        unsafe { RegCloseKey(cls) };
    }
    unsafe { RegCloseKey(root) };

    let mut out = Vec::new();
    for path in paths {
        if let Ok(h) = open_raw(&path, false) {
            if let Some((caps, pid)) = caps_of(h) {
                if caps.usage_page == page && caps.usage == usage {
                    out.push(Candidate {
                        path,
                        usage_page: caps.usage_page,
                        usage: caps.usage,
                        input_len: caps.input_report_byte_length,
                        feature_len: caps.feature_report_byte_length,
                        product_id: pid,
                    });
                }
            }
            unsafe { CloseHandle(h) };
        }
    }
    out
}

fn out_empty() -> Vec<Candidate> {
    Vec::new()
}

pub struct Dev {
    pub path: String,
    h: HANDLE,
    ov: OVERLAPPED,
    input_len: usize,
    feature_len: usize,
}

impl Dev {
    pub fn open(cand: &Candidate) -> Result<Self, io::Error> {
        let h = open_raw(&cand.path, true)?;
        // Auto-reset event: a manual-reset one stays signaled after the first
        // completed read and every later WaitForSingleObject returns instantly,
        // mistaking stale signals for finished I/O.
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null_mut()) };
        let ov = OVERLAPPED {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: ev,
        };
        Ok(Self {
            path: cand.path.clone(),
            h,
            ov,
            input_len: cand.input_len.max(8) as usize,
            feature_len: cand.feature_len.max(8) as usize,
        })
    }

    /// Reopen by known device path without re-enumeration (fast reconnect).
    /// Used when a handle dies but the device is still present — avoids the
    /// full registry scan + caps probe that `enumerate()` + `open()` require.
    pub fn open_path(path: &str) -> Result<Self, io::Error> {
        let h = open_raw(path, true)?;
        let caps = match caps_of(h) {
            Some((caps, _)) => caps,
            None => {
                unsafe { CloseHandle(h) };
                return Err(io::Error::new(io::ErrorKind::Other, "HID caps unavailable"));
            }
        };
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null_mut()) };
        let ov = OVERLAPPED {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: ev,
        };
        Ok(Self {
            path: path.to_string(),
            h,
            ov,
            input_len: caps.input_report_byte_length.max(8) as usize,
            feature_len: caps.feature_report_byte_length.max(8) as usize,
        })
    }

    pub fn set_feature(&self, frame8: &[u8; 8]) -> Result<(), io::Error> {
        let fns = hid_fns().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "hid.dll unavailable"))?;
        let mut buf = vec![0u8; self.feature_len];
        let n = frame8.len().min(buf.len());
        buf[..n].copy_from_slice(&frame8[..n]);
        // Probed on the 60HE v2: the FF55 feature report ID is 1 (hidraw's
        // leading-zero convention does not survive HidD_SetFeature on Windows).
        buf[0] = 0x01;
        if unsafe { (fns.set_feature)(self.h, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    /// Overlapped read with timeout; Ok(0) on timeout.
    pub fn read_timeout(&mut self, out: &mut [u8], ms: u32) -> Result<usize, io::Error> {
        unsafe {
            std::ptr::write_bytes(&mut self.ov as *mut OVERLAPPED as *mut u8, 0, std::mem::size_of::<OVERLAPPED>() - std::mem::size_of::<HANDLE>());
            let mut n = 0u32;
            let ok = ReadFile(self.h, out.as_mut_ptr(), out.len() as u32, &mut n, &mut self.ov);
            if ok != 0 {
                return Ok(n as usize);
            }
            let err = GetLastError();
            if err != 997 {
                // ERROR_IO_PENDING expected for overlapped
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let w = WaitForSingleObject(self.ov.h_event, ms);
            if w == WAIT_TIMEOUT {
                CancelIo(self.h);
                let mut discard = 0u32;
                GetOverlappedResult(self.h, &mut self.ov, &mut discard, 1);
                return Ok(0);
            }
            if w != WAIT_OBJECT_0 {
                return Err(last_error());
            }
            if GetOverlappedResult(self.h, &mut self.ov, &mut n, 0) == 0 {
                return Err(last_error());
            }
            Ok(n as usize)
        }
    }

    pub fn drain(&mut self) {
        let mut buf = vec![0u8; self.input_len.max(64)];
        for _ in 0..16 {
            match self.read_timeout(&mut buf, 0) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe {
            if !self.ov.h_event.is_null() {
                CloseHandle(self.ov.h_event);
            }
            CloseHandle(self.h);
        }
    }
}

pub fn enumerate_all() -> Vec<Candidate> {
    enumerate(0xff55, 1)
}
