use serde::Serialize;
use std::sync::Mutex;
use tauri::{ipc::Channel, AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

const RELEASE_URL: &str = "https://github.com/huuhungn/ShardBrowser/releases/latest";

#[derive(Default)]
struct Pending {
    update: Option<Update>,
    bytes: Option<Vec<u8>>,
    downloading: bool,
}

#[derive(Default)]
pub struct PendingUpdate(Mutex<Pending>);

#[derive(Serialize)]
pub struct LauncherUpdateInfo {
    current: String,
    latest: Option<String>,
    update_available: bool,
    release_url: String,
    notes: Option<String>,
    pub_date: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DownloadEvent {
    Started { content_length: Option<u64> },
    Progress { chunk_length: usize },
    Finished,
}

fn lock_pending(state: &PendingUpdate) -> Result<std::sync::MutexGuard<'_, Pending>, String> {
    state
        .0
        .lock()
        .map_err(|_| "Updater state is unavailable.".to_string())
}

#[tauri::command]
pub async fn launcher_update_check(
    app: AppHandle,
    pending: State<'_, PendingUpdate>,
) -> Result<LauncherUpdateInfo, String> {
    let current = app.package_info().version.to_string();
    let update = app
        .updater_builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?;

    let info = match update.as_ref() {
        Some(update) => LauncherUpdateInfo {
            current,
            latest: Some(update.version.clone()),
            update_available: true,
            release_url: RELEASE_URL.into(),
            notes: update.body.clone(),
            pub_date: update.date.map(|date| date.to_string()),
        },
        None => LauncherUpdateInfo {
            current,
            latest: None,
            update_available: false,
            release_url: RELEASE_URL.into(),
            notes: None,
            pub_date: None,
        },
    };

    *lock_pending(&pending)? = Pending {
        update,
        bytes: None,
        downloading: false,
    };
    Ok(info)
}

#[tauri::command]
pub async fn launcher_update_download(
    pending: State<'_, PendingUpdate>,
    on_event: Channel<DownloadEvent>,
) -> Result<(), String> {
    let update = {
        let mut state = lock_pending(&pending)?;
        if state.downloading {
            return Err(crate::errcode::code("updater.downloadInProgress"));
        }
        let update = state
            .update
            .clone()
            .ok_or_else(|| "Check for updates before downloading.".to_string())?;
        state.downloading = true;
        update
    };

    let mut started = false;
    let result = update
        .download(
            |chunk_length, content_length| {
                if !started {
                    started = true;
                    let _ = on_event.send(DownloadEvent::Started { content_length });
                }
                let _ = on_event.send(DownloadEvent::Progress { chunk_length });
            },
            || {
                let _ = on_event.send(DownloadEvent::Finished);
            },
        )
        .await;

    let mut state = lock_pending(&pending)?;
    state.downloading = false;
    match result {
        Ok(bytes) => {
            state.update = Some(update);
            state.bytes = Some(bytes);
            Ok(())
        }
        Err(error) => {
            state.update = Some(update);
            state.bytes = None;
            Err(error.to_string())
        }
    }
}

#[tauri::command]
pub fn launcher_update_install(pending: State<'_, PendingUpdate>) -> Result<(), String> {
    let (update, bytes) = {
        let mut state = lock_pending(&pending)?;
        if state.downloading {
            return Err(crate::errcode::code("updater.waitForDownload"));
        }
        let update = state
            .update
            .take()
            .ok_or_else(|| "Check for updates before installing.".to_string())?;
        let bytes = match state.bytes.take() {
            Some(bytes) => bytes,
            None => {
                state.update = Some(update);
                return Err(crate::errcode::code("updater.downloadBeforeInstall"));
            }
        };
        (update, bytes)
    };

    if let Err(error) = update.install(&bytes) {
        let mut state = lock_pending(&pending)?;
        state.update = Some(update);
        state.bytes = Some(bytes);
        return Err(error.to_string());
    }
    Ok(())
}

#[tauri::command]
pub fn launcher_update_restart(app: AppHandle) {
    app.restart();
}

#[cfg(test)]
mod updater_signing_tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use minisign_verify::{PublicKey, Signature};
    use serde_json::Value;
    use std::{env, fs, path::Path};

    #[test]
    #[ignore = "release workflow supplies a disposable artifact signed by the repository secret"]
    fn updater_private_key_matches_shipped_public_key() {
        let artifact = env::var("SHARDX_UPDATER_TEST_ARTIFACT")
            .expect("SHARDX_UPDATER_TEST_ARTIFACT must point to the signed fixture");
        let signature = env::var("SHARDX_UPDATER_TEST_SIGNATURE")
            .expect("SHARDX_UPDATER_TEST_SIGNATURE must point to its signature");
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");

        let config: Value =
            serde_json::from_slice(&fs::read(config_path).expect("read tauri.conf.json"))
                .expect("parse tauri.conf.json");
        let encoded_key = config
            .pointer("/plugins/updater/pubkey")
            .and_then(Value::as_str)
            .expect("Tauri updater public key is missing");
        let public_key_text =
            String::from_utf8(STANDARD.decode(encoded_key).expect("decode public key"))
                .expect("public key must be UTF-8");
        let public_key = PublicKey::decode(&public_key_text).expect("parse public key");
        let encoded_signature = fs::read_to_string(signature).expect("read updater signature");
        let signature_text = String::from_utf8(
            STANDARD
                .decode(encoded_signature.trim())
                .expect("decode updater signature"),
        )
        .expect("updater signature must be UTF-8");
        let signature = Signature::decode(&signature_text).expect("parse updater signature");
        let artifact = fs::read(artifact).expect("read updater fixture");

        public_key
            .verify(&artifact, &signature, true)
            .expect("updater private key does not match the public key shipped by the Launcher");

        let mut tampered = artifact;
        if let Some(first) = tampered.first_mut() {
            *first ^= 0x01;
        } else {
            tampered.push(0x01);
        }
        assert!(
            public_key.verify(&tampered, &signature, true).is_err(),
            "a modified updater artifact must not pass signature verification"
        );
    }
}
