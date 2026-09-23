fn main() {
    // Test binaries get no application manifest, so they load comctl32 v5 --
    // which has no `TaskDialogIndirect`. Anything in the dependency tree that
    // imports it then fails to start with STATUS_ENTRYPOINT_NOT_FOUND before
    // a single test runs. The app binary gets this from its own manifest;
    // tests have to ask for it explicitly.
    #[cfg(windows)]
    println!(
        "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' \
         name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
         processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
    );

    tauri_build::build()
}
