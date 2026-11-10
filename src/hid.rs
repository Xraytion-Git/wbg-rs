//! Raw Win32 HID layer (no C toolchain): standard SetupDi enumeration +
//! hid.dll.  Uses SetupDiGetClassDevs + HID class GUID for portable device
//! discovery across all Windows machines (registry scanning is machine-specific).

use std::ffi::c_void;
use std::io;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub h_event: HANDLE,
}

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x102;
#[allow(dead_code)]
pub const INFINITE: u32 = 0xffffffff;

pub type HANDLE = *mut c_void;

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
        name: *const u16, access: u32, share: u32, sec: *mut c_void,
        disp: u32, flags: u32, tmpl: HANDLE,
    ) -> HANDLE;
    fn ReadFile(h: HANDLE, buf: *mut u8, len: u32, read: *mut u32, ov: *mut OVERLAPPED) -> i32;
    fn CloseHandle(h: HANDLE) -> i32;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn GetOverlappedResult(h: HANDLE, ov: *mut OVERLAPPED, n: *mut u32, wait: i32) -> i32;
    fn CancelIo(h: HANDLE) -> i32;
    fn CreateEventW(sec: *mut c_void, manual: i32, initial: i32, name: *const u16) -> HANDLE;
    fn LoadLibraryW(name: *const u16) -> HANDLE;
    fn GetProcAddress(mod_: HANDLE, name: *const u8) -> *mut c_void;
}

// SetupDi API for portable HID enumeration
#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class: *const c_void,
        enumerator: *const u16,
        parent: *mut c_void,
        flags: u32,
    ) -> HANDLE;
    fn SetupDiEnumDeviceInterfaces(
        set: HANDLE,
        dev_info: *mut c_void,
        class: *const c_void,
        idx: u32,
        iface: *mut SP_DEVICE_INTERFACE_DATA,
    ) -> i32;
    fn SetupDiGetDeviceInterfaceDetailW(
        set: HANDLE,
        iface: *mut SP_DEVICE_INTERFACE_DATA,
        detail: *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W,
        detail_size: u32,
        required: *mut u32,
        dev_info: *mut c_void,
    ) -> i32;
    fn SetupDiDestroyDeviceInfoList(set: HANDLE) -> i32;
}

// HID GUID: {4d1e55b2-f16f-11cf-88cb-001111000030}
static HID_CLASS_GUID: [u32; 4] = [0x4d1e55b2, 0xf16f11cf, 0x00110000, 0x03000000];

#[repr(C)]
#[derive(Clone, Copy)]
struct SP_DEVICE_INTERFACE_DATA {
    cb_size: u32,
    interface_class_guid: [u32; 4],
    flags: u32,
    reserved: usize,
}

#[repr(C)]
struct SP_DEVICE_INTERFACE_DETAIL_DATA_W {
    cb_size: u32,
    device_path: [u16; 1],
}

const DIGCF_PRESENT: u32 = 0x02;
const DIGCF_DEVICEINTERFACE: u32 = 0x10;

// hid.dll dynamic loading
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
    HID_FNS.get_or_init(|| unsafe {
        let name = "hid.dll\0".encode_utf16().collect::<Vec<u16>>();
        let module = LoadLibraryW(name.as_ptr());
        if module.is_null() {
            return None;
        }
        let sym = |n: &[u8]| -> Option<*mut c_void> {
            let mut name = n.to_vec();
            name.push(0);
            let p = GetProcAddress(module, name.as_ptr());
            if p.is_null() { None } else { Some(p) }
        };
        Some(HidFns {
            get_attributes: std::mem::transmute(sym(b"HidD_GetAttributes")?),
            get_preparsed: std::mem::transmute(sym(b"HidD_GetPreparsedData")?),
            free_preparsed: std::mem::transmute(sym(b"HidD_FreePreparsedData")?),
            get_caps: std::mem::transmute(sym(b"HidP_GetCaps")?),
            set_feature: std::mem::transmute(sym(b"HidD_SetFeature")?),
        })
    })
    .as_ref()
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_raw(path: &str, rw: bool) -> Result<HANDLE, io::Error> {
    let wname = wstr(path);
    let h = unsafe {
        CreateFileW(
            wname.as_ptr(),
            if rw { GENERIC_READ | GENERIC_WRITE } else { GENERIC_READ },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if h as isize == -1 {
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
        let mut pp: *mut c_void = std::ptr::null_mut();
        if (fns.get_preparsed)(h, &mut pp) == 0 || pp.is_null() {
            return None;
        }
        let mut caps = HIDP_CAPS {
            usage: 0, usage_page: 0,
            input_report_byte_length: 0, output_report_byte_length: 0,
            feature_report_byte_length: 0,
            reserved: [0; 17],
            number_link_collection_nodes: 0,
            number_input_button_caps: 0, number_input_value_caps: 0,
            number_input_data_indices: 0,
            number_output_button_caps: 0, number_output_value_caps: 0,
            number_output_data_indices: 0,
            number_feature_button_caps: 0, number_feature_value_caps: 0,
            number_feature_data_indices: 0,
        };
        let ok = (fns.get_caps)(pp, &mut caps);
        (fns.free_preparsed)(pp);
        if ok != 0x00110000 {
            return None;
        }
        Some((caps, attrs.product_id))
    }
}

/// HID interface description: device path + usage coordinates + report sizes.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub path: String,
    #[allow(dead_code)]
    pub usage_page: u16,
    #[allow(dead_code)]
    pub usage: u16,
    pub input_len: u16,
    pub feature_len: u16,
    #[allow(dead_code)]
    pub product_id: u16,
}

/// Portable HID enumeration via SetupDiGetClassDevs + HID class GUID.
/// Works on all Windows machines (unlike registry scanning which is
/// machine-specific).  Logs ALL found HID devices for diagnostics.
pub fn enumerate(page: u16, usage: u16) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut all_count = 0u32;
    unsafe {
        let set = SetupDiGetClassDevsW(
            HID_CLASS_GUID.as_ptr() as *const c_void,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if set as isize == -1 {
            crate::log("hid: SetupDiGetClassDevsW failed");
            return out;
        }

        let mut idx = 0u32;
        loop {
            let mut iface = SP_DEVICE_INTERFACE_DATA {
                cb_size: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
                interface_class_guid: [0; 4],
                flags: 0,
                reserved: 0,
            };
            if SetupDiEnumDeviceInterfaces(set, std::ptr::null_mut(), HID_CLASS_GUID.as_ptr() as *const c_void, idx, &mut iface) == 0 {
                break;
            }
            idx += 1;

            let mut required = 0u32;
            SetupDiGetDeviceInterfaceDetailW(set, &mut iface, std::ptr::null_mut(), 0, &mut required, std::ptr::null_mut());
            if required == 0 {
                continue;
            }

            let mut detail_buf = vec![0u8; required as usize];
            let detail = detail_buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
            (*detail).cb_size = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;

            if SetupDiGetDeviceInterfaceDetailW(set, &mut iface, detail, required, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                continue;
            }

            let path_start = &(*detail).device_path as *const u16;
            let mut len = 0;
            while *path_start.add(len) != 0 {
                len += 1;
            }
            let path = String::from_utf16_lossy(std::slice::from_raw_parts(path_start, len));
            all_count += 1;

            // Log every HID device found
            if let Ok(h) = open_raw(&path, false) {
                if let Some((caps, pid)) = caps_of(h) {
                    let match_ = caps.usage_page == page && caps.usage == usage;
                    crate::log(&format!(
                        "hid[{}]: page=0x{:04x} usage={} pid=0x{:04x} in={} feat={} {} path={}",
                        idx, caps.usage_page, caps.usage, pid,
                        caps.input_report_byte_length, caps.feature_report_byte_length,
                        if match_ { "MATCH" } else { "" },
                        &path[..path.len().min(80)]
                    ));
                    if match_ {
                        out.push(Candidate {
                            path,
                            usage_page: caps.usage_page,
                            usage: caps.usage,
                            input_len: caps.input_report_byte_length,
                            feature_len: caps.feature_report_byte_length,
                            product_id: pid,
                        });
                    }
                } else {
                    crate::log(&format!("hid[{}]: open OK but caps failed path={}", idx, &path[..path.len().min(60)]));
                }
                CloseHandle(h);
            } else {
                crate::log(&format!("hid[{}]: open FAILED path={}", idx, &path[..path.len().min(60)]));
            }
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    crate::log(&format!("hid: enumerate done — {} HID interfaces total, {} matched", all_count, out.len()));
    out
}

/// Enumerate all Wooting FF55 control interfaces.
pub fn enumerate_all() -> Vec<Candidate> {
    enumerate(0xff55, 1)
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
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null_mut()) };
        let ov = OVERLAPPED {
            internal: 0, internal_high: 0,
            offset: 0, offset_high: 0,
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
            internal: 0, internal_high: 0,
            offset: 0, offset_high: 0,
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
        buf[0] = 0x01;
        if unsafe { (fns.set_feature)(self.h, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    /// Overlapped read with timeout; Ok(0) on timeout.
    pub fn read_timeout(&mut self, out: &mut [u8], ms: u32) -> Result<usize, io::Error> {
        unsafe {
            std::ptr::write_bytes(
                &mut self.ov as *mut OVERLAPPED as *mut u8,
                0,
                std::mem::size_of::<OVERLAPPED>() - std::mem::size_of::<HANDLE>(),
            );
            let mut n = 0u32;
            let ok = ReadFile(self.h, out.as_mut_ptr(), out.len() as u32, &mut n, &mut self.ov);
            if ok != 0 {
                return Ok(n as usize);
            }
            let err = GetLastError();
            if err != 997 {
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
