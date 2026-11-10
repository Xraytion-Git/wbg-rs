//! System tray icon with context menu.
//! Right-click (or left-click) shows: autostart toggle + exit.

use std::ffi::c_void;

type HWND = *mut c_void;
type HICON = *mut c_void;
type HMENU = *mut c_void;
type HINSTANCE = *mut c_void;
type HBRUSH = *mut c_void;
type HCURSOR = *mut c_void;

// ---- user32 ----
#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(cls: *const WNDCLASSEXW) -> u16;
    fn CreateWindowExW(
        ex: u32,
        cls: *const u16,
        title: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: HWND,
        menu: HMENU,
        instance: HINSTANCE,
        param: *mut c_void,
    ) -> HWND;
    fn DefWindowProcW(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> isize;
    fn LoadIconW(instance: HINSTANCE, name: *const u16) -> HICON;
    fn LoadCursorW(instance: HINSTANCE, name: *const u16) -> HCURSOR;
    fn CreatePopupMenu() -> HMENU;
    fn AppendMenuW(menu: HMENU, flags: u32, id: usize, text: *const u16) -> i32;
    fn TrackPopupMenu(
        menu: HMENU,
        flags: u32,
        x: i32,
        y: i32,
        reserved: i32,
        hwnd: HWND,
        rect: *const c_void,
    ) -> i32;
    fn DestroyMenu(menu: HMENU) -> i32;
    fn GetCursorPos(pt: *mut POINT) -> i32;
    fn PostQuitMessage(code: i32);
    fn PostMessageW(hwnd: HWND, msg: u32, wparam: usize, lparam: isize) -> i32;
    fn SetForegroundWindow(hwnd: HWND) -> i32;
}

// ---- shell32 ----
#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(dw_message: u32, data: *mut NOTIFYICONDATAW) -> i32;
}

// ---- kernel32 ----
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
}

// ---- constants ----
const NIM_ADD: u32 = 0;
const NIM_DELETE: u32 = 2;
const NIF_ICON: u32 = 0x2;
const NIF_MESSAGE: u32 = 0x1;
const NIF_TIP: u32 = 0x4;
const NIF_SHOWTIP: u32 = 0x80;

const WM_NULL: u32 = 0x0000;
const WM_COMMAND: u32 = 0x0111;
const WM_DESTROY: u32 = 0x0002;
const WM_APP: u32 = 0x8000;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONUP: u32 = 0x0205;

const MF_STRING: u32 = 0x0;
const MF_CHECKED: u32 = 0x8;
const MF_SEPARATOR: u32 = 0x800;

const TPM_RIGHTBUTTON: u32 = 0x0002;
const TPM_RETURNCMD: u32 = 0x0100;

const IDI_APPLICATION: *const u16 = 32512 as *const u16;
const IDC_ARROW: *const u16 = 32512 as *const u16;

const HWND_MESSAGE: HWND = (-3isize) as HWND;

const MENU_AUTOSTART: usize = 1001;
const MENU_EXIT: usize = 1002;

// ---- structures ----
#[repr(C)]
#[derive(Clone, Copy)]
struct POINT {
    x: i32,
    y: i32,
}

#[repr(C)]
struct WNDCLASSEXW {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: Option<unsafe extern "system" fn(HWND, u32, usize, isize) -> isize>,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: HINSTANCE,
    h_icon: HICON,
    h_cursor: HCURSOR,
    hbr_background: HBRUSH,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: HICON,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NOTIFYICONDATAW {
    cb_size: u32,
    hwnd: HWND,
    u_id: u32,
    u_flags: u32,
    u_callback_message: u32,
    h_icon: HICON,
    sz_tip: [u16; 128],
    dw_state: u32,
    dw_state_mask: u32,
    sz_info: [u16; 256],
    u_timeout_or_version: u32,
    sz_info_title: [u16; 64],
    dw_info_flags: u32,
    guid_item: [u8; 16],
    h_balloon_icon: HICON,
}

fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---- tray icon data (global so wnd_proc can access it) ----
static mut TRAY_DATA: Option<NOTIFYICONDATAW> = None;

unsafe fn remove_tray_icon() {
    if let Some(ref mut d) = TRAY_DATA {
        Shell_NotifyIconW(NIM_DELETE, d as *mut _);
    }
}

// ---- window procedure ----
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        // Tray notification
        WM_APP => {
            match lparam as u32 {
                WM_LBUTTONUP | WM_RBUTTONUP => {
                    show_menu(hwnd);
                }
                _ => {}
            }
            0
        }
        // Menu command (not used with TPM_RETURNCMD, but kept as fallback)
        WM_COMMAND => {
            match wparam & 0xFFFF {
                MENU_AUTOSTART => {
                    toggle_autostart();
                }
                MENU_EXIT => {
                    remove_tray_icon();
                    PostQuitMessage(0);
                    std::process::exit(0);
                }
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            remove_tray_icon();
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn show_menu(hwnd: HWND) {
    let autostart = crate::api::autostart_enabled();
    let menu = CreatePopupMenu();
    let label_autostart = wstr("\u{5f00}\u{673a}\u{542f}\u{52a8}"); // 开机启动
    let label_exit = wstr("\u{9000}\u{51fa}"); // 退出
    let flags = MF_STRING | if autostart { MF_CHECKED } else { 0 };
    AppendMenuW(menu, flags, MENU_AUTOSTART, label_autostart.as_ptr());
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(menu, MF_STRING, MENU_EXIT, label_exit.as_ptr());

    // Standard popup-menu pattern: foreground + show + WM_NULL
    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD,
        pt.x,
        pt.y,
        0,
        hwnd,
        std::ptr::null(),
    );
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);

    match cmd as usize {
        MENU_AUTOSTART => {
            toggle_autostart();
        }
        MENU_EXIT => {
            remove_tray_icon();
            PostQuitMessage(0);
            std::process::exit(0);
        }
        _ => {}
    }
}

fn toggle_autostart() {
    let current = crate::api::autostart_enabled();
    crate::api::autostart_set(!current);
    crate::log(&format!(
        "tray: autostart toggled {} -> {}",
        current,
        !current
    ));
}

// ---- entry point (called from main in a spawned thread) ----
pub fn start_tray() {
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = wstr("wbg_rs_tray");

        // Register window class
        let wc = WNDCLASSEXW {
            cb_size: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfn_wnd_proc: Some(wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: instance,
            h_icon: LoadIconW(std::ptr::null_mut(), IDI_APPLICATION),
            h_cursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbr_background: std::ptr::null_mut(),
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name.as_ptr(),
            h_icon_sm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);

        // Create message-only window (invisible, receives tray messages)
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wstr("wbg-rs").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null_mut(),
        );

        // Add tray icon
        let icon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        let tip = wstr("wbg-rs \u{952e}\u{76d8}\u{914d}\u{7f6e}\u{670d}\u{52a1}"); // wbg-rs 键盘配置服务
        let mut nid = NOTIFYICONDATAW {
            cb_size: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hwnd,
            u_id: 1,
            u_flags: NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP,
            u_callback_message: WM_APP,
            h_icon: icon,
            sz_tip: [0u16; 128],
            dw_state: 0,
            dw_state_mask: 0,
            sz_info: [0u16; 256],
            u_timeout_or_version: 0,
            sz_info_title: [0u16; 64],
            dw_info_flags: 0,
            guid_item: [0u8; 16],
            h_balloon_icon: std::ptr::null_mut(),
        };
        for (i, &c) in tip.iter().enumerate().take(127) {
            nid.sz_tip[i] = c;
        }
        TRAY_DATA = Some(nid);
        Shell_NotifyIconW(NIM_ADD, &mut nid);

        crate::log("tray: icon added, right-click for menu");

        // Message pump
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

// ---- MSG struct + message pump (duplicated here to keep tray self-contained) ----
#[repr(C)]
struct MSG {
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: POINT,
}

#[link(name = "user32")]
extern "system" {
    fn GetMessageW(msg: *mut MSG, hwnd: HWND, min: u32, max: u32) -> i32;
    fn TranslateMessage(msg: *const MSG) -> i32;
    fn DispatchMessageW(msg: *const MSG) -> isize;
}
