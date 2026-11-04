# G2-48 manual check: the Windows credential store

ADR 0002 Q-29 makes the evidence for G2-48 a log from this real Windows
machine: a credential filed the way the launcher files its device keys
survives a restart, is readable while the session is locked and after it is
unlocked, and what a logon session started without your password gets. The
automated half (a fresh process, the mock store made unavailable, the key
file) runs in `cargo test --lib` (`credential::tests`); it is the evidence
that the launcher fails closed when the store is unavailable.

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
   without your password. Two results are expected:
   - `PASS store unavailable to the probe: ... read error <nonzero> (no
     value) ...` when Windows gives the task no credential store;
   - `OBSERVED store readable by the probe: ... read error 0 (value
     returned, digest match True) ...` when it does. On Windows 11 (build
     26300, 2026-11-04) an S4U task of a user who is signed in read the
     test credential, so this is the result to expect while you are signed
     in. It records how Windows behaves; it is not a launcher fault.

   Either way the line ends `own session afterwards: digest match True`. The
   phase prints `FAIL` only when your own copy is damaged or the probe
   returns something else. The task is removed when the phase ends. Without
   elevation the phase prints `SKIPPED` and exits with code 2.

5. Clean up, in a normal PowerShell:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\g2-48-credential-check.ps1 -Phase Cleanup
   ```

   Expect `PASS deleted ...; read afterwards error 1168`.

## Evidence

Send the log the last line names (`%LOCALAPPDATA%\shardx-g2-48\g2-48-<run
id>.log`). G2-48 passes when, for one run id, the last result line of
Store, Verify, Locked and Cleanup is `PASS` and the last result line of
Unavailable is `PASS` or `OBSERVED`. A phase may be rerun (a Locked run where
the session was never locked prints `FAIL ... while locked 0`); its last
result counts. A phase that is missing, or whose last result is `FAIL`,
leaves the row open.
