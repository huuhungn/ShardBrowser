//! The GPU-capability probe against the engine actually installed on this
//! machine.
//!
//! The unit tests cover the verdict arithmetic with hand-written capability
//! sets, which proves the comparison but not the acquisition: they would pass
//! unchanged if the probe never launched the engine, if the devtools handshake
//! drifted, or if the evaluated expression returned a shape `serde` refuses.
//! Only a real launch proves the launcher and the engine still agree.
//!
//! Skipped, not failed, when no engine is installed — a fresh checkout has no
//! runtime yet, and a test suite that cannot pass before first install is a
//! test suite people learn to ignore.

use shardx_launcher_lib::gpu_caps;

/// The engine answers the probe, and the answer describes real hardware.
#[tokio::test]
async fn the_installed_engine_reports_this_machine_s_own_gpu() {
    let Ok(binary) = shardx_launcher_lib::runtime_binary_path_for_tests() else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };
    if !binary.exists() {
        eprintln!("skipped: engine runtime is not installed at {}", binary.display());
        return;
    }

    // force: the cache may hold an answer from a previous run, and a cache hit
    // would test the JSON file rather than the engine.
    let caps = gpu_caps::probe(true).await.expect("probe the installed engine");

    // A real driver names itself. The empty string is what a failed read or a
    // silently-dropped devtools reply leaves behind, so it is the interesting
    // thing to rule out.
    assert!(
        !caps.renderer.trim().is_empty(),
        "renderer should name the host GPU, got {:?}",
        caps.renderer,
    );
    assert!(
        !caps.vendor.trim().is_empty(),
        "vendor should name the host GPU vendor, got {:?}",
        caps.vendor,
    );

    // Every WebGL1 implementation worth the name carries these. Their absence
    // means the probe read a software fallback or nothing at all, which is the
    // failure mode that made this test worth writing.
    assert!(
        caps.webgl1.len() >= 5,
        "a real WebGL1 context exposes many extensions, got {}: {:?}",
        caps.webgl1.len(),
        caps.webgl1,
    );
    assert!(
        caps.webgl2.len() >= 3,
        "a real WebGL2 context exposes several extensions, got {}: {:?}",
        caps.webgl2.len(),
        caps.webgl2,
    );

    // The cache is keyed by engine version; an empty key would make every
    // later run miss and re-launch the engine.
    assert!(
        !caps.engine_version.trim().is_empty(),
        "probe should stamp the engine version it asked",
    );

    // Second call, no force: must come back from disk without launching.
    let started = std::time::Instant::now();
    let hit = gpu_caps::probe(false).await.expect("cached probe");
    assert_eq!(hit.renderer, caps.renderer, "cache should return the same answer");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a cache hit must not relaunch the engine (took {:?})",
        started.elapsed(),
    );
}

/// A fingerprint claiming an extension this host lacks is reported, and one
/// claiming only what the host has is not.
#[tokio::test]
async fn the_verdict_is_drawn_against_what_the_engine_reported() {
    let Ok(binary) = shardx_launcher_lib::runtime_binary_path_for_tests() else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };
    if !binary.exists() {
        eprintln!("skipped: engine runtime is not installed");
        return;
    }

    let caps = gpu_caps::probe(false).await.expect("probe the installed engine");

    // Built from the host's own answer, so this is compatible by construction
    // on any machine the test runs on.
    let honest = serde_json::json!({
        "webgl": {
            "extensions": caps.webgl1.clone(),
            "extensions_v2": caps.webgl2.clone(),
        }
    });
    let verdict = gpu_caps::compat(&honest, &caps);
    assert!(
        verdict.compatible,
        "a fingerprint claiming exactly what the host has must pass, missing: {:?} / {:?}",
        verdict.missing_webgl1,
        verdict.missing_webgl2,
    );

    // No driver ships an extension by this name.
    let mut inflated = caps.webgl1.clone();
    inflated.push("WEBGL_extension_that_does_not_exist".to_string());
    let lying = serde_json::json!({
        "webgl": {
            "extensions": inflated,
            "extensions_v2": caps.webgl2.clone(),
        }
    });
    let verdict = gpu_caps::compat(&lying, &caps);
    assert!(!verdict.compatible, "an unbackable claim must be reported");
    assert!(
        verdict.missing_webgl1.iter().any(|m| m.contains("does_not_exist")),
        "the verdict should name the offending extension, got {:?}",
        verdict.missing_webgl1,
    );
}
