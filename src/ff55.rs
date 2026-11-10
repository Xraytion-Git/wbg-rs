//! FF55 control-interface wire protocol for Wooting keyboards.
//! Framing cross-validated against two independent sources:
//! - logixism/open-wbg-service src/hid.rs (MIT, SOLO ❯ CODES)
//! - apfelgriebsch/KeyProfileBridge bin/keyprofile-bridge (MIT)
//! Feature OUT: [report_id=0, 0xD1, 0xDA, cmd, param u32 LE] (8 bytes)
//! Input IN:   [id(1..6)?, 0xD1, 0xDA, cmd_echo(0|cmd), status, body_len u16 LE, body]
//! status 0x88 = ok, 0x66 = unsupported.

#[allow(dead_code)]
pub const VENDOR: u16 = 0x31e3;
#[allow(dead_code)]
pub const CONTROL_PAGE: u16 = 0xff55;
#[allow(dead_code)]
pub const CONTROL_USAGE: u16 = 1;

pub const CMD_CURRENT: u8 = 0x0b;
pub const CMD_ACTIVATE: u8 = 0x17;
pub const CMD_METADATA: u8 = 0x37;
pub const CMD_COUNT: u8 = 0x3e;
pub const CMD_SELECT_LINKED: u8 = 0x54;
pub const CMD_LINKED: u8 = 0x55;
pub const CMD_APP_COUNT: u8 = 0x56;
pub const CMD_APP: u8 = 0x57;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProfileId {
    pub namespace: u8,
    pub index: u8,
}

impl ProfileId {
    pub fn parameter(self) -> u32 {
        u32::from(self.namespace) << 8 | u32::from(self.index)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppFilter {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedApp {
    pub name: String,
    pub steam_id: Option<u32>,
    pub match_type: u32,
    pub filters: Vec<AppFilter>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub id: ProfileId,
    pub name: String,
    pub apps: Vec<LinkedApp>,
}

pub fn command_frame(command: u8, param: u32) -> [u8; 8] {
    let mut f = [0u8; 8];
    f[1] = 0xd1;
    f[2] = 0xda;
    f[3] = command;
    f[4..8].copy_from_slice(&param.to_le_bytes());
    f
}

pub struct Reply<'a> {
    pub status: u8,
    pub body: &'a [u8],
}

pub fn parse_reply(raw: &[u8], expected_command: u8) -> Result<Reply<'_>, String> {
    let offset = if raw.starts_with(&[0xd1, 0xda]) {
        0
    } else {
        if raw.first().map(|id| (1..=6).contains(id)) != Some(true) {
            return Err("not an FF55 input report".into());
        }
        (1..=4)
            .find(|&o| raw.get(o..o + 2) == Some(&[0xd1, 0xda]) && raw[1..o].iter().all(|b| *b == 0))
            .ok_or("missing FF55 magic in input-report prefix")?
    };
    let data = &raw[offset..];
    if data.len() < 6 {
        return Err("short FF55 reply header".into());
    }
    if data[2] != 0 && data[2] != expected_command {
        return Err(format!(
            "stale/unexpected command 0x{:02x}, expected 0x{expected_command:02x}",
            data[2]
        ));
    }
    let body_len = usize::from(u16::from_le_bytes([data[4], data[5]]));
    if body_len > data.len() - 6 {
        return Err(format!(
            "truncated FF55 reply body: announced {body_len}, received {}",
            data.len() - 6
        ));
    }
    Ok(Reply {
        status: data[3],
        body: &data[6..6 + body_len],
    })
}

// ---- bounded protobuf reader (unknown fields skipped) ----

enum Field<'a> {
    Integer(u64),
    Bytes(&'a [u8]),
    Other,
}

struct Fields<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Fields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for i in 0..10 {
            let b = *self.data.get(self.pos).ok_or("truncated protobuf varint")?;
            self.pos += 1;
            if i == 9 && b > 1 {
                return Err("protobuf varint exceeds u64".into());
            }
            value |= u64::from(b & 0x7f) << (i * 7);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("protobuf varint exceeds 10 bytes".into())
    }
    fn next(&mut self) -> Result<Option<(u64, Field<'a>)>, String> {
        if self.pos == self.data.len() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let number = tag >> 3;
        if number == 0 {
            return Err("protobuf field zero is invalid".into());
        }
        let field = match tag & 7 {
            0 => Field::Integer(self.varint()?),
            1 | 5 => {
                let n = if tag & 7 == 1 { 8 } else { 4 };
                let end = self.pos.checked_add(n).ok_or("protobuf overflow")?;
                if end > self.data.len() {
                    return Err("truncated protobuf fixed-width field".into());
                }
                self.pos = end;
                Field::Other
            }
            2 => {
                let size = self.varint()? as usize;
                let end = self.pos.checked_add(size).ok_or("protobuf overflow")?;
                if end > self.data.len() {
                    return Err("truncated protobuf length-delimited field".into());
                }
                let bytes = &self.data[self.pos..end];
                self.pos = end;
                Field::Bytes(bytes)
            }
            w => return Err(format!("unsupported protobuf wire type {w}")),
        };
        Ok(Some((number, field)))
    }
}

/// Decode a firmware string. Wootility values may carry invisible junk —
/// trailing NUL padding and Unicode direction/format marks (U+200E etc.) —
/// which survives printing but poisons equality comparisons. Strip both.
fn text(bytes: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "invalid UTF-8")?;
    Ok(s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{061c}' | '\u{feff}')
        })
        .collect::<String>()
        .trim()
        .to_owned())
}

pub fn metadata_name(data: &[u8]) -> Result<String, String> {
    let mut fields = Fields::new(data);
    let mut name = None;
    while let Some((n, f)) = fields.next()? {
        if let (1, Field::Bytes(v)) = (n, f) {
            name = Some(text(v)?);
        }
    }
    name.ok_or("profile metadata has no name field".into())
}

fn parse_filter(data: &[u8]) -> Result<Option<AppFilter>, String> {
    let mut fields = Fields::new(data);
    let mut filter = None;
    while let Some((n, f)) = fields.next()? {
        let kind = match n {
            1 => "process_name",
            2 => "process_directory",
            3 => "window_title",
            4 => "process_full_path",
            _ => continue,
        };
        if let Field::Bytes(v) = f {
            filter = Some(AppFilter {
                kind: kind.into(),
                value: text(v)?,
            });
        }
    }
    Ok(filter)
}

fn parse_custom_app(data: &[u8], app: &mut LinkedApp) -> Result<(), String> {
    let mut fields = Fields::new(data);
    while let Some((n, f)) = fields.next()? {
        match (n, f) {
            (1, Field::Integer(v)) => app.match_type = v as u32,
            (2, Field::Bytes(v)) => {
                if let Some(filter) = parse_filter(v)? {
                    app.filters.push(filter);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn parse_app(data: &[u8]) -> Result<LinkedApp, String> {
    let mut app = LinkedApp {
        name: String::new(),
        steam_id: None,
        match_type: 0,
        filters: Vec::new(),
    };
    let mut fields = Fields::new(data);
    while let Some((n, f)) = fields.next()? {
        match (n, f) {
            (1, Field::Bytes(v)) => app.name = text(v)?,
            (2, Field::Bytes(v)) => parse_custom_app(v, &mut app)?,
            (3, Field::Integer(v)) => app.steam_id = Some(v as u32),
            _ => {}
        }
    }
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_layout_matches_reference() {
        let good = [1, 0xd1, 0xda, 0x37, 0x88, 2, 0, 0x0a, 0];
        let r = parse_reply(&good, 0x37).unwrap();
        assert_eq!(r.body, &[0x0a, 0]);
        assert_eq!(r.status, 0x88);
        assert!(parse_reply(&good, 0x3e).is_err());
    }

    #[test]
    fn app_parse_matches_reference() {
        let app = [
            0x0a, 4, b'T', b'e', b's', b't', 0x12, 14, 8, 1, 0x12, 10, 0x1a, 8, b'K', b'e', b'y',
            b'b', b'o', b'a', b'r', b'd', 0x18, 0xac, 2, 0x20, 3,
        ];
        let parsed = parse_app(&app).unwrap();
        assert_eq!(parsed.name, "Test");
        assert_eq!(parsed.steam_id, Some(300));
        assert_eq!(parsed.match_type, 1);
        assert_eq!(parsed.filters.len(), 1);
        assert_eq!(parsed.filters[0].kind, "window_title");
    }
}
