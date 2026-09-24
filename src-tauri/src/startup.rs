use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_autostart::ManagerExt;

use crate::settings::{self, Settings};

pub const AUTOSTART_ARG: &str = "--shardx-autostart";

#[cfg(target_os = "windows")]
const RESTART_FLAGS: u32 = windows_sys::Win32::System::Recovery::RESTART_NO_CRASH
    | windows_sys::Win32::System::Recovery::RESTART_NO_HANG
    | windows_sys::Win32::System::Recovery::RESTART_NO_PATCH;

#[derive(Debug, Clone, Serialize)]
pub struct StartupStatus {
    pub supported: bool,
    pub configured: bool,
    pub registered: bool,
    pub matches_configuration: bool,
    pub start_minimized: bool,
    pub launched_for_autostart: bool,
    pub api_enabled: bool,
    pub api_mode: &'static str,
    pub mcp_mode: &'static str,
}

pub fn args_request_autostart<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|arg| arg.as_ref() == AUTOSTART_ARG)
}

pub fn launched_for_autostart() -> bool {
    std::env::args().any(|arg| arg == AUTOSTART_ARG)
}

fn registration_enabled(app: &AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

fn set_registration(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    if enabled {
        // `enable` rewrites the executable path, which keeps the entry correct
        // after an in-place update or when a portable build has moved.
        manager.enable().map_err(|e| e.to_string())?;
        if !manager.is_enabled().map_err(|e| e.to_string())? {
            return Err(crate::errcode::code("startup.osDidNotEnable"));
        }
    } else {
        // A Windows user can disable an existing Run entry in Task Manager.
        // In that state `is_enabled` is false although the entry still exists,
        // so attempt removal and accept a missing-entry error only when the
        // final observed state is disabled.
        if let Err(error) = manager.disable() {
            if manager.is_enabled().map_err(|e| e.to_string())? {
                return Err(error.to_string());
            }
        }
        if manager.is_enabled().map_err(|e| e.to_string())? {
            return Err(crate::errcode::code("startup.osDidNotDisable"));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn sync_restart_registration(enabled: bool) -> Result<(), String> {
    use windows_sys::Win32::System::Recovery::{
        RegisterApplicationRestart, UnregisterApplicationRestart,
    };

    let result = if enabled {
        let args = AUTOSTART_ARG
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe { RegisterApplicationRestart(args.as_ptr(), RESTART_FLAGS) }
    } else {
        unsafe { UnregisterApplicationRestart() }
    };

    if result < 0 {
        Err(crate::errcode::code_with(
            "startup.restartRegistrationFailed",
            &[("hresult", &format!("0x{:08X}", result as u32))],
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn sync_restart_registration(_enabled: bool) -> Result<(), String> {
    Ok(())
}

pub fn status(app: &AppHandle) -> Result<StartupStatus, String> {
    let configured = settings::load().map_err(|e| e.to_string())?;
    let registered = registration_enabled(app)?;
    Ok(StartupStatus {
        supported: true,
        configured: configured.launch_at_login,
        registered,
        matches_configuration: configured.launch_at_login == registered,
        start_minimized: configured.start_minimized,
        launched_for_autostart: launched_for_autostart(),
        api_enabled: configured.api_enabled,
        api_mode: "launcher_embedded",
        mcp_mode: "client_spawned",
    })
}

/// Persist all Launcher settings and apply an explicit launch-at-login change
/// transactionally. Unrelated Settings saves do not override a user disabling
/// the entry in the operating system's own startup UI.
pub fn save(app: &AppHandle, next: &Settings) -> Result<(), String> {
    let previous = settings::load().map_err(|e| e.to_string())?;
    let registration_changed = previous.launch_at_login != next.launch_at_login;
    let previous_registered = registration_enabled(app)?;

    if registration_changed {
        set_registration(app, next.launch_at_login)?;
    }

    let effective_registered =
        next.launch_at_login && (registration_changed || previous_registered);
    if let Err(error) = sync_restart_registration(effective_registered) {
        if registration_changed {
            let _ = set_registration(app, previous_registered);
        }
        let _ = sync_restart_registration(previous.launch_at_login && previous_registered);
        return Err(error);
    }

    if let Err(error) = settings::save(next) {
        if registration_changed {
            let _ = set_registration(app, previous_registered);
        }
        let _ = sync_restart_registration(previous.launch_at_login && previous_registered);
        return Err(error.to_string());
    }

    Ok(())
}

/// Apply an explicit startup configuration request even when the saved value
/// already matches. This reconciles an entry changed in the OS startup UI.
pub fn configure(app: &AppHandle, next: &Settings) -> Result<(), String> {
    let previous = settings::load().map_err(|e| e.to_string())?;
    let previous_registered = registration_enabled(app)?;
    set_registration(app, next.launch_at_login)?;

    if let Err(error) = sync_restart_registration(next.launch_at_login) {
        let _ = set_registration(app, previous_registered);
        let _ = sync_restart_registration(previous_registered);
        return Err(error);
    }

    if let Err(error) = settings::save(next) {
        let _ = set_registration(app, previous_registered);
        let _ = sync_restart_registration(previous.launch_at_login && previous_registered);
        return Err(error.to_string());
    }

    Ok(())
}

/// Refresh an already-enabled entry with the current executable path. If the
/// OS reports the entry disabled (for example via Task Manager), respect that
/// external choice rather than silently re-enabling it.
pub fn refresh_registration_path(app: &AppHandle, configured: &Settings) -> Result<(), String> {
    let registered = registration_enabled(app)?;
    if configured.launch_at_login && registered {
        set_registration(app, true)?;
    }
    sync_restart_registration(configured.launch_at_login && registered)
}

pub fn should_start_hidden(configured: &Settings, autostart_launch: bool) -> bool {
    autostart_launch && configured.launch_at_login && configured.start_minimized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_the_dedicated_autostart_argument() {
        assert!(args_request_autostart(["launcher.exe", AUTOSTART_ARG]));
        assert!(!args_request_autostart(["launcher.exe", "--background"]));
        assert!(!args_request_autostart([
            "launcher.exe",
            "--shardx-autostart-extra"
        ]));
    }

    #[test]
    fn hides_only_an_enabled_minimized_autostart_launch() {
        let mut configured = Settings {
            launch_at_login: true,
            start_minimized: true,
            ..Default::default()
        };
        assert!(should_start_hidden(&configured, true));

        configured.start_minimized = false;
        assert!(!should_start_hidden(&configured, true));
        configured.start_minimized = true;
        configured.launch_at_login = false;
        assert!(!should_start_hidden(&configured, true));
        assert!(!should_start_hidden(&configured, false));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_resume_uses_the_autostart_argument() {
        use windows_sys::Win32::System::Recovery::GetApplicationRestartSettings;

        sync_restart_registration(true).unwrap();
        let mut command_line = [0u16; 256];
        let mut size = command_line.len() as u32;
        let mut flags = 0u32;
        let result = unsafe {
            GetApplicationRestartSettings(
                -1isize as _,
                command_line.as_mut_ptr(),
                &mut size,
                &mut flags,
            )
        };
        sync_restart_registration(false).unwrap();

        assert!(result >= 0);
        let end = command_line
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(command_line.len());
        assert_eq!(
            String::from_utf16_lossy(&command_line[..end]),
            AUTOSTART_ARG
        );
        assert_eq!(flags, RESTART_FLAGS);
    }
}
