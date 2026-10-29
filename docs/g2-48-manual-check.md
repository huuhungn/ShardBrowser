# G2-48 manual check: the Windows credential store

ADR 0002 Q-31 makes the evidence for G2-48 a log from this real Windows
machine: a credential filed the way the launcher files its device keys
survives a restart, is readable while the session is locked and after it is
unlocked, and is not handed out to a logon session that has no credential
store. The automated half (a fresh process, the mock store made unavailable,
the key file) runs in `cargo test --lib` (`credential::tests`).

The script `scripts/g2-48-credential-check.ps1` only touches one test
credential it creates, named `g2-48-manual-<run id>.shardx-launcher`, which
holds 32 random bytes made for this check. The log records that name, Win32
error codes and the SHA-256 of the test value, never the value. The launcher
and its data in `%APPDATA%\shardx-launcher` are not touched.

## Steps

Run every command from the repository root in a normal (not elevated)
PowerShell, except step 4.

1. Store the test credential:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Store
   ```

   Expect a `PASS stored ...` line.

2. Restart Windows (Start > Power > Restart), sign in, then:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Verify
   ```

   Expect `PASS after restart True`. Without a restart it prints `FAIL after
   restart False`.

3. Locked session:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Locked
   ```

   Within a few seconds press Win+L, wait about 30 seconds, sign in again and
   wait until the 90 seconds are over. Expect `PASS samples ok while locked N,
   while unlocked M, failed 0` with both N and M above 0.

4. Unavailable store, from an elevated PowerShell (Run as administrator),
   because it registers a short-lived S4U scheduled task for your account:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Unavailable -StateDir "$env:LOCALAPPDATA\shardx-g2-48"
   ```

   Pass `-StateDir` as shown: an elevated prompt of another administrator
   account would otherwise look in that account's folder. The task runs
   without your password, so Windows gives it no credential store. Expect
   `PASS store unavailable to the probe: ... read error <nonzero> (no value)
   ...; own session afterwards: digest match True`. The task is removed
   when the phase ends. Without elevation the phase prints `SKIPPED` and
   exits with code 2.

5. Clean up, in a normal PowerShell:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Cleanup
   ```

   Expect `PASS deleted ...; read afterwards error 1168`.

## Evidence

Send the log the last line names (`%LOCALAPPDATA%\shardx-g2-48\g2-48-<run
id>.log`). G2-48 passes when it holds a `PASS` line for each of Store,
Verify, Locked, Unavailable and Cleanup from one run id. A `FAIL` line, or a
phase that is missing, leaves the row open.
