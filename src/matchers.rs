//! App → linked-profile matching. Rules live on the keyboard (linked apps with
//! filters); an app matches when its filters all match (AND), first matching
//! profile wins. Steam-only apps (steam_id, no filters) resolve through the
//! installed-apps inventory (applist.json, shared with the stock service).
//! Wootility's `process_directory` filter value may be a directory OR a full
//! exe path — accept both.

use crate::ff55::{LinkedApp, Profile, ProfileId};
use crate::win32::Foreground;

fn ci_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn ci_contains(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Directory match: exact or path-boundary prefix ("D:\Games" never matches
/// "D:\Games2").  Normalises both slash styles so filters written with `/`
/// (e.g. by Wootility or manual editing) match Windows `\` paths.
fn dir_matches(dir: &str, value: &str) -> bool {
    let d = dir.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    let v = value.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    d == v || d.starts_with(&format!("{v}\\"))
}

pub struct Rules {
    pub profiles: Vec<Profile>,
    pub steam: Vec<(u32, String)>,
}

impl Rules {
    pub fn load_inventory() -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let base = std::env::var("APPDATA").unwrap_or_default();
        let p = std::path::PathBuf::from(&base).join("wooting-bg-service").join("applist.json");
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(list) = v.get("steam").and_then(|s| s.as_array()) {
                    for e in list {
                        if let (Some(id), Some(path)) =
                            (e.get("app_id").and_then(|x| x.as_u64()), e.get("path").and_then(|x| x.as_str()))
                        {
                            out.push((id as u32, path.trim_end_matches('\\').to_string()));
                        }
                    }
                }
            }
        }
        out
    }

    fn steam_matches(&self, steam_id: u32, fg: &Foreground) -> bool {
        self.steam
            .iter()
            .any(|(id, dir)| *id == steam_id && dir_matches(&fg.dir, dir) || *id == steam_id && dir_matches(&fg.exe_path, dir))
    }

    fn app_matches(&self, app: &LinkedApp, fg: &Foreground) -> bool {
        if let Some(sid) = app.steam_id {
            if self.steam_matches(sid, fg) {
                return true;
            }
        }
        if app.filters.is_empty() {
            return false;
        }
        app.filters.iter().all(|f| match f.kind.as_str() {
            "process_name" => {
                ci_eq(&fg.exe_name, &f.value)
                    || ci_eq(&fg.exe_name, &format!("{}.exe", f.value))
                    || ci_eq(&fg.exe_name, f.value.trim_end_matches(".exe"))
            }
            "process_directory" => {
                let v = f.value.replace('/', "\\");
                if v.to_ascii_lowercase().ends_with(".exe") {
                    ci_eq(&fg.exe_path, &v)
                        || v
                            .rsplit_once('\\')
                            .map(|(d, _)| dir_matches(&fg.dir, d))
                            .unwrap_or(false)
                } else {
                    dir_matches(&fg.dir, &v)
                }
            }
            "process_full_path" => {
                ci_eq(&fg.exe_path, &f.value)
                    || ci_eq(&fg.exe_path, &f.value.replace('/', "\\"))
            }
            "window_title" => ci_contains(&fg.title, &f.value),
            _ => false,
        })
    }

    /// Desired linked profile for the foreground window.
    pub fn desired(&self, fg: &Foreground) -> Option<ProfileId> {
        for p in &self.profiles {
            if p.id.namespace != 1 {
                continue;
            }
            for app in &p.apps {
                if self.app_matches(app, fg) {
                    return Some(p.id);
                }
            }
        }
        None
    }

    pub fn profile_name(&self, id: ProfileId) -> String {
        self.profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("{}/{}", id.namespace, id.index))
    }
}
