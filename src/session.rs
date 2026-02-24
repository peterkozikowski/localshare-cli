use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct Session {
    pub pid: u32,
    pub target_port: u16,
    pub listen_port: u16,
    pub public_addr: String,
    pub connection_string: String,
    pub started_at: String,
}

fn sessions_dir() -> anyhow::Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("could not find home directory"))?
        .join(".localshare")
        .join("sessions");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn session_file(target_port: u16) -> anyhow::Result<PathBuf> {
    Ok(sessions_dir()?.join(format!("{}.json", target_port)))
}

pub fn save(session: &Session) -> anyhow::Result<()> {
    let path = session_file(session.target_port)?;
    let json = serde_json::to_string_pretty(session)?;
    fs::write(&path, json)?;
    Ok(())
}

pub fn remove(target_port: u16) -> anyhow::Result<()> {
    let path = session_file(target_port)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

fn is_pid_alive(pid: u32) -> bool {
    // Send signal 0 to check if process exists
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

pub fn list_active() -> anyhow::Result<Vec<Session>> {
    let dir = sessions_dir()?;
    let mut sessions = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(sessions),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let content = fs::read_to_string(&path)?;
            if let Ok(session) = serde_json::from_str::<Session>(&content) {
                if is_pid_alive(session.pid) {
                    sessions.push(session);
                } else {
                    // Stale session file, clean it up
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    sessions.sort_by_key(|s| s.target_port);
    Ok(sessions)
}

pub fn find_by_port(target_port: u16) -> anyhow::Result<Option<Session>> {
    let path = session_file(target_port)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let session: Session = serde_json::from_str(&content)?;
    if is_pid_alive(session.pid) {
        Ok(Some(session))
    } else {
        let _ = fs::remove_file(&path);
        Ok(None)
    }
}
