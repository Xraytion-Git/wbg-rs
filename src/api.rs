//! Wootility compatibility API: gRPC-web over HTTP on 127.0.0.1:50052.
//! Wire format reverse-engineered from logixism/open-wbg-service src/api.rs
//! (MIT) against Wootility 5.4.2's protobuf-ts transport:
//!   POST /wooting_service.WootilityService/<Method>
//!   POST /data_source_manager_service.DataSourceManagerCommunicationService/<Method>
//!   POST /app_linking.AppLinkingService/<Method>
//!   GET  /status
//! Request body = one uncompressed gRPC-web data frame [0x00, len BE32, pb]
//! (whole body base64 in text mode); response = data frame + trailer frame
//! [0x80, len, "grpc-status: N\r\n..."].

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::{log, win32};

const WOOT: &str = "/wooting_service.WootilityService/";
const DATA: &str = "/data_source_manager_service.DataSourceManagerCommunicationService/";
const APP: &str = "/app_linking.AppLinkingService/";

// ---- minimal protobuf writer ----

fn varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    varint(out, u64::from(field << 3 | wire));
}

fn pb_str(out: &mut Vec<u8>, field: u32, s: &str) {
    tag(out, field, 2);
    varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn pb_bool(out: &mut Vec<u8>, field: u32, b: bool) {
    tag(out, field, 0);
    varint(out, b as u64);
}

fn pb_u64(out: &mut Vec<u8>, field: u32, v: u64) {
    tag(out, field, 0);
    varint(out, v);
}

fn pb_msg(out: &mut Vec<u8>, field: u32, inner: &[u8]) {
    tag(out, field, 2);
    varint(out, inner.len() as u64);
    out.extend_from_slice(inner);
}

/// First field-1 varint of a message (Enabled/AppRequest alike).
fn pb_first_varint(data: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < data.len() {
        let mut tag = 0u64;
        let mut sh = 0;
        loop {
            let b = *data.get(i)?;
            i += 1;
            tag |= u64::from(b & 0x7f) << sh;
            if b & 0x80 == 0 {
                break;
            }
            sh += 7;
        }
        if tag >> 3 == 1 && tag & 7 == 0 {
            let mut v = 0u64;
            let mut sh = 0;
            loop {
                let b = *data.get(i)?;
                i += 1;
                v |= u64::from(b & 0x7f) << sh;
                if b & 0x80 == 0 {
                    return Some(v);
                }
                sh += 7;
            }
        }
        // skip other wire types best-effort
        return None;
    }
    None
}

// ---- gRPC-web framing ----

fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn trailer(code: u32, message: &str) -> Vec<u8> {
    let mut t = format!("grpc-status: {code}\r\n");
    if !message.is_empty() {
        t.push_str("grpc-message: ");
        for b in message.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                t.push(b as char);
            } else {
                t.push_str(&format!("%{b:02X}"));
            }
        }
        t.push_str("\r\n");
    }
    frame(0x80, t.as_bytes())
}

fn base64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = u32::from(c[0]) << 16 | u32::from(*c.get(1).unwrap_or(&0)) << 8 | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0;
    for &b in s {
        if b == b'=' || b == b'\r' || b == b'\n' {
            continue;
        }
        acc = acc << 6 | val(b)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

// ---- HTTP plumbing ----

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let clen = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < clen {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(clen.max(body.len().min(clen)));
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8], origin: Option<&str>, extra: &[(&str, &str)]) {
    let code = match status {
        200 => "200 OK",
        204 => "204 No Content",
        403 => "403 Forbidden",
        405 => "405 Method Not Allowed",
        415 => "415 Unsupported Media Type",
        _ => "500 Internal Server Error",
    };
    let mut head = format!("HTTP/1.1 {code}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n", body.len());
    if status == 204 {
        head = format!("HTTP/1.1 {code}\r\nContent-Length: 0\r\n");
    }
    if let Some(o) = origin {
        head.push_str(&format!("Access-Control-Allow-Origin: {o}\r\nVary: Origin\r\n"));
    }
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

// ---- service logic ----

fn grpc_body(payload: &[u8], err: Option<(u32, &str)>, text: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some((code, msg)) = err {
        out.extend_from_slice(&trailer(code, msg));
    } else {
        out.extend_from_slice(&frame(0x00, payload));
        out.extend_from_slice(&trailer(0, ""));
    }
    if text {
        base64_std(&out).into_bytes()
    } else {
        out
    }
}

fn app_inventory() -> serde_json::Value {
    let p = std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
        .join("wooting-bg-service")
        .join("applist.json");
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn encode_apps() -> Vec<u8> {
    let inv = app_inventory();
    let mut apps = Vec::new();
    if let Some(list) = inv.get("steam").and_then(|v| v.as_array()) {
        for e in list {
            let mut s = Vec::new();
            if let Some(n) = e.get("game_name").and_then(|v| v.as_str()) {
                pb_str(&mut s, 1, n);
            }
            if let Some(id) = e.get("app_id").and_then(|v| v.as_u64()) {
                pb_u64(&mut s, 3, id);
            }
            pb_msg(&mut apps, 1, &s);
        }
    }
    if let Some(list) = inv.get("disk").and_then(|v| v.as_array()) {
        for e in list {
            let mut d = Vec::new();
            if let Some(n) = e.get("name").and_then(|v| v.as_str()) {
                pb_str(&mut d, 1, n);
            }
            if let Some(p) = e.get("path").and_then(|v| v.get("Directory")).and_then(|v| v.as_str()) {
                pb_str(&mut d, 4, p);
            }
            pb_msg(&mut apps, 2, &d);
        }
    }
    apps
}

fn encode_open_windows() -> Vec<u8> {
    let mut out = Vec::new();
    for w in win32::visible_windows() {
        let mut m = Vec::new();
        pb_str(&mut m, 1, &w.title);
        pb_u64(&mut m, 2, w.pid);
        pb_str(&mut m, 3, &w.path);
        pb_str(&mut m, 4, &w.name);
        pb_msg(&mut out, 1, &m);
    }
    out
}

fn invoke(path: &str, body: &[u8]) -> Result<Vec<u8>, (u32, String)> {
    if let Some(m) = path.strip_prefix(WOOT) {
        match m {
            "Heartbeat" => {
                let mut out = Vec::new();
                pb_str(&mut out, 1, concat!("wbg-rs ", env!("CARGO_PKG_VERSION")));
                pb_bool(&mut out, 2, autostart_enabled());
                Ok(out)
            }
            "GetAutoStartEnabled" => {
                let mut out = Vec::new();
                pb_bool(&mut out, 1, autostart_enabled());
                Ok(out)
            }
            "SetAutoStartEnabled" => {
                let on = pb_first_varint(body).unwrap_or(1) != 0;
                autostart_set(on);
                Ok(Vec::new())
            }
            "GetAppSwitchNotificationEnabled" => {
                let mut out = Vec::new();
                pb_bool(&mut out, 1, false);
                Ok(out)
            }
            "SetAppSwitchNotificationEnabled" | "OpenLogFolder" => Ok(Vec::new()),
            "CheckForUpdates" | "TriggerUpdate" => {
                Err((9, "No update feed is available for wbg-rs".into()))
            }
            _ => Err((12, format!("Wootility method {m} is not implemented"))),
        }
    } else if let Some(m) = path.strip_prefix(DATA) {
        match m {
            // 60HE v2 has no external lightbar: empty point/source sets are
            // the complete feature surface for this keyboard.
            "GetAllDataPointInfo" | "GetAllDataSources" => Ok(Vec::new()),
            "SetDataSourceEnabled" => Ok(Vec::new()),
            _ => Err((12, format!("Data source method {m} is not implemented"))),
        }
    } else if let Some(m) = path.strip_prefix(APP) {
        match m {
            "GetLinkableApps" => Ok(encode_apps()),
            "GetOpenWindows" => Ok(encode_open_windows()),
            _ => Err((12, format!("App linking method {m} is not implemented"))),
        }
    } else {
        Err((12, "Unknown gRPC method".into()))
    }
}

fn autostart_enabled() -> bool {
    // Registry read via FFI: spawning reg.exe from this GUI-subsystem process
    // would create a visible console window on every heartbeat (user-visible
    // flashing), so the hot path must never create processes.
    use std::ffi::c_void;
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(root: *mut c_void, sub: *const u16, opts: u32, sam: u32, out: *mut *mut c_void) -> i32;
        fn RegQueryValueExW(key: *mut c_void, name: *const u16, res: *mut u32, typ: *mut u32, data: *mut u8, len: *mut u32) -> i32;
        fn RegCloseKey(key: *mut c_void) -> i32;
    }
    fn wstr(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let hkcu = (0x8000_0001u32 as i32 as isize) as *mut c_void;
    let key = wstr(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
    let val = wstr("WootingBGService");
    unsafe {
        let mut h: *mut c_void = std::ptr::null_mut();
        if RegOpenKeyExW(hkcu, key.as_ptr(), 0, 0x20019, &mut h) != 0 {
            return false;
        }
        let mut len = 0u32;
        let q = RegQueryValueExW(
            h,
            val.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        );
        RegCloseKey(h);
        q == 0 && len > 0
    }
}

fn autostart_set(on: bool) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Writes still go through signed reg.exe (unsigned processes are blocked
    // from Run-key writes on this machine), but silently.
    let exe = std::env::current_exe()
        .map(|p| format!("\"{}\"", p.to_string_lossy()))
        .unwrap_or_default();
    let mut cmd = std::process::Command::new("reg");
    cmd.creation_flags(CREATE_NO_WINDOW);
    if on {
        cmd.args([
            "add",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "WootingBGService",
            "/d",
            &exe,
            "/f",
        ]);
    } else {
        cmd.args([
            "delete",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "WootingBGService",
            "/f",
        ]);
    }
    let _ = cmd.output();
}

fn handle(mut stream: TcpStream) {
    let req = match read_request(&mut stream) {
        Some(r) => r,
        None => return,
    };
    // DNS-rebinding guard, same allow-list as the reference implementation.
    if let Some(host) = req.header("host") {
        let ok = ["localhost:50052", "127.0.0.1:50052", "[::1]:50052"]
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h));
        if !ok {
            write_response(&mut stream, 403, "text/plain", b"", None, &[]);
            return;
        }
    }
    let origin = req.header("origin").map(|s| s.to_string());
    if req.method == "OPTIONS" {
        write_response(
            &mut stream,
            204,
            "text/plain",
            b"",
            origin.as_deref(),
            &[
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                (
                    "Access-Control-Allow-Headers",
                    "content-type, x-grpc-web, x-user-agent, grpc-timeout, accept",
                ),
                ("Access-Control-Max-Age", "600"),
            ],
        );
        return;
    }
    if req.method == "GET" && req.path == "/status" {
        write_response(
            &mut stream,
            200,
            "application/json",
            br#"{"ok":true,"service":"wbg-rs"}"#,
            origin.as_deref(),
            &[],
        );
        return;
    }
    if req.method != "POST" {
        write_response(&mut stream, 405, "text/plain", b"", origin.as_deref(), &[]);
        return;
    }
    let ctype = req.header("content-type").unwrap_or("");
    let text = ctype.contains("grpc-web-text");
    if !(ctype.contains("application/grpc-web")) {
        write_response(&mut stream, 415, "text/plain", b"", origin.as_deref(), &[]);
        return;
    }
    let raw = if text {
        match base64_decode(&req.body) {
            Some(d) => d,
            None => {
                let body = grpc_body(b"", Some((3, "Invalid gRPC-Web base64")), text);
                write_response(&mut stream, 200, ctype, &body, origin.as_deref(), &[]);
                return;
            }
        }
    } else {
        req.body.clone()
    };
    let payload = if raw.len() >= 5 && raw[0] == 0 {
        let len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
        if len == raw.len() - 5 {
            raw[5..].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    // Streaming endpoint: hold the connection; this keyboard has no data points.
    if req.path.ends_with("/ListenToDataPointUpdates") {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }
    let result = invoke(&req.path, &payload);
    let body = match result {
        Ok(pb) => grpc_body(&pb, None, text),
        Err((code, msg)) => grpc_body(b"", Some((code, &msg)), text),
    };
    let out_ctype = if text {
        "application/grpc-web-text+proto"
    } else {
        "application/grpc-web+proto"
    };
    write_response(&mut stream, 200, out_ctype, &body, origin.as_deref(), &[]);
}

pub fn serve() {
    let listener = match TcpListener::bind("127.0.0.1:50052") {
        Ok(l) => l,
        Err(e) => {
            log(&format!("api: bind 50052 failed: {e}"));
            return;
        }
    };
    log("api: listening on 127.0.0.1:50052");
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            std::thread::spawn(move || handle(s));
        }
    }
}
