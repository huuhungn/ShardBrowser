<#
.SYNOPSIS
  G2-48 manual evidence: a test-only credential in the Windows Credential
  Manager across a restart, a locked session and an unavailable store.

.DESCRIPTION
  Run the phases in order on the real machine (docs/g2-48-manual-check.md):

    Store        before the restart: files a random 32-byte test credential
                 the way the launcher files its keys (generic credential,
                 target "<ref>.shardx-launcher", persistence Local) and reads
                 it back.
    Verify       after the restart: reads it back and compares digests.
    Locked       samples the credential every 5 s while you lock the session
                 (Win+L) and unlock it again.
    Unavailable  runs a probe in a logon session that has no credential store
                 (an S4U scheduled task; needs an elevated prompt) and checks
                 that it gets an error, never the value. Then checks that the
                 credential is unchanged in your own session.
    Cleanup      deletes the test credential and checks it is gone.

  Every phase appends timestamped lines to the run's log in -StateDir. The log
  holds the target name, Win32 error codes and the SHA-256 of the test value,
  never the value itself. The value is random, created for this check only,
  and protects nothing.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Store', 'Verify', 'Locked', 'Unavailable', 'Cleanup', 'Probe')]
    [string]$Phase,
    [string]$StateDir = (Join-Path $env:LOCALAPPDATA 'shardx-g2-48'),
    [int]$LockedSeconds = 90,
    # Internal: where the Probe phase writes its result.
    [string]$ProbeOut
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

Add-Type -Namespace G248 -Name Cred -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct CREDENTIAL {
    public uint Flags; public uint Type; public string TargetName; public string Comment;
    public long LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob;
    public uint Persist; public uint AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
}
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredWriteW(ref CREDENTIAL c, uint flags);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredReadW(string target, uint type, uint flags, out IntPtr c);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredDeleteW(string target, uint type, uint flags);
[DllImport("advapi32.dll")]
public static extern void CredFree(IntPtr c);

public static int Write(string target, string user, byte[] blob) {
    var c = new CREDENTIAL();
    c.Type = 1; // CRED_TYPE_GENERIC
    c.TargetName = target; c.UserName = user;
    c.Persist = 2; // CRED_PERSIST_LOCAL_MACHINE: never roams
    c.CredentialBlobSize = (uint)blob.Length;
    c.CredentialBlob = Marshal.AllocHGlobal(blob.Length);
    try {
        Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
        return CredWriteW(ref c, 0) ? 0 : Marshal.GetLastWin32Error();
    } finally { Marshal.FreeHGlobal(c.CredentialBlob); }
}
// Returns the Win32 error (0 on success); blob and persist are set on success.
public static int Read(string target, out byte[] blob, out uint persist) {
    blob = null; persist = 0;
    IntPtr p;
    if (!CredReadW(target, 1, 0, out p)) return Marshal.GetLastWin32Error();
    try {
        var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
        blob = new byte[c.CredentialBlobSize];
        Marshal.Copy(c.CredentialBlob, blob, 0, blob.Length);
        persist = c.Persist;
        return 0;
    } finally { CredFree(p); }
}
public static int Delete(string target) {
    return CredDeleteW(target, 1, 0) ? 0 : Marshal.GetLastWin32Error();
}
'@

$statePath = Join-Path $StateDir 'state.json'

function Get-Digest([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Write-Log([string]$message) {
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('o'), $Phase, $message
    Add-Content -LiteralPath $script:log -Value $line -Encoding utf8
    Write-Host $line
}

function Test-Locked {
    # LogonUI.exe runs while the session is locked.
    [bool](Get-Process -Name LogonUI -ErrorAction SilentlyContinue)
}

# UTC ticks, so the value survives the JSON round trip unchanged.
function Get-BootTime {
    [long](Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks
}

# Reads the credential and compares it with the stored digest.
function Test-Credential($state) {
    $blob = $null; $persist = 0
    $err = [G248.Cred]::Read($state.target, [ref]$blob, [ref]$persist)
    if ($err -ne 0) { return @{ ok = $false; detail = "CredRead error $err" } }
    $digest = Get-Digest $blob
    [Array]::Clear($blob, 0, $blob.Length)
    $ok = ($digest -eq $state.sha256) -and ($persist -eq 2)
    @{ ok = $ok; detail = "digest match $($digest -eq $state.sha256), persist $persist (2 = local machine)" }
}

if ($Phase -eq 'Probe') {
    # Runs inside the S4U task: no password, so no credential store.
    $blob = $null; $persist = 0
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $readErr = [G248.Cred]::Read($state.target, [ref]$blob, [ref]$persist)
    $writeErr = [G248.Cred]::Write("$($state.target).probe", $state.ref, [byte[]](1..32))
    if ($writeErr -eq 0) { [void][G248.Cred]::Delete("$($state.target).probe") }
    $got = if ($readErr -eq 0) { "value returned, digest match $((Get-Digest $blob) -eq $state.sha256)" } else { 'no value' }
    Set-Content -LiteralPath $ProbeOut -Encoding utf8 -Value ("user {0}; read error {1} ({2}); write error {3}" -f [Environment]::UserName, $readErr, $got, $writeErr)
    exit 0
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

if ($Phase -eq 'Store') {
    if (Test-Path -LiteralPath $statePath) { throw "A run is in progress ($statePath). Run -Phase Cleanup first." }
    $runId = [guid]::NewGuid().ToString('N')
    $ref = "g2-48-manual-$runId"
    $state = [ordered]@{
        runId = $runId; ref = $ref; target = "$ref.shardx-launcher"
        storedAt = (Get-Date).ToUniversalTime().ToString('o'); bootAtStore = (Get-BootTime)
        log = (Join-Path $StateDir "g2-48-$runId.log"); sha256 = ''
    }
    $script:log = $state.log
    $blob = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($blob)
    $state.sha256 = Get-Digest $blob
    $err = [G248.Cred]::Write($state.target, $ref, $blob)
    [Array]::Clear($blob, 0, $blob.Length)
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
    Write-Log "machine $env:COMPUTERNAME user $env:USERNAME boot $($state.bootAtStore)"
    if ($err -ne 0) { Write-Log "FAIL CredWrite error $err for $($state.target)"; exit 1 }
    $check = Test-Credential $state
    Write-Log ("{0} stored {1}, sha256 {2}; read back: {3}" -f ($(if ($check.ok) { 'PASS' } else { 'FAIL' })), $state.target, $state.sha256, $check.detail)
    if (-not $check.ok) { exit 1 }
    Write-Log 'next: restart Windows, sign in, run -Phase Verify'
    exit 0
}

if (-not (Test-Path -LiteralPath $statePath)) { throw "No run in progress: run -Phase Store first." }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$script:log = $state.log

switch ($Phase) {
    'Verify' {
        $boot = Get-BootTime
        # Boot times a few seconds apart are the same boot read twice.
        $restarted = [math]::Abs($boot - [long]$state.bootAtStore) -gt 50000000
        $check = Test-Credential $state
        Write-Log ("{0} after restart {1} (boot {2}, at store {3}); {4}" -f ($(if ($check.ok -and $restarted) { 'PASS' } else { 'FAIL' })), $restarted, $boot, $state.bootAtStore, $check.detail)
        if (-not ($check.ok -and $restarted)) { exit 1 }
    }
    'Locked' {
        Write-Log "sampling for $LockedSeconds s: lock the session now (Win+L), wait 30 s, unlock"
        $deadline = (Get-Date).AddSeconds($LockedSeconds)
        $lockedOk = 0; $unlockedOk = 0; $failed = 0
        while ((Get-Date) -lt $deadline) {
            $locked = Test-Locked
            $check = Test-Credential $state
            if (-not $check.ok) { $failed++ } elseif ($locked) { $lockedOk++ } else { $unlockedOk++ }
            Write-Log ("sample locked {0}: {1} {2}" -f $locked, ($(if ($check.ok) { 'ok' } else { 'FAIL' })), $check.detail)
            Start-Sleep -Seconds 5
        }
        $pass = ($failed -eq 0) -and ($lockedOk -gt 0) -and ($unlockedOk -gt 0)
        Write-Log ("{0} samples ok while locked {1}, while unlocked {2}, failed {3}" -f ($(if ($pass) { 'PASS' } else { 'FAIL' })), $lockedOk, $unlockedOk, $failed)
        if (-not $pass) { exit 1 }
    }
    'Unavailable' {
        $task = "shardx-g2-48-probe-$($state.runId)"
        $out = Join-Path $StateDir 'probe.txt'
        Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" -Phase Probe -StateDir `"{1}`" -ProbeOut `"{2}`"" -f $PSCommandPath, $StateDir, $out)
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
        try {
            Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
        } catch {
            Write-Log "SKIPPED the S4U probe could not be registered ($($_.Exception.Message)); run this phase from an elevated PowerShell"
            exit 2
        }
        try {
            Start-ScheduledTask -TaskName $task
            $until = (Get-Date).AddSeconds(60)
            while (-not (Test-Path -LiteralPath $out) -and (Get-Date) -lt $until) { Start-Sleep -Seconds 1 }
        } finally {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false
        }
        if (-not (Test-Path -LiteralPath $out)) { Write-Log 'FAIL the probe wrote no result within 60 s'; exit 1 }
        $probe = (Get-Content -LiteralPath $out -Raw).Trim()
        Remove-Item -LiteralPath $out
        $refused = $probe -match 'read error [1-9]\d* \(no value\)'
        $check = Test-Credential $state
        Write-Log ("{0} store unavailable to the probe: {1}; own session afterwards: {2}" -f ($(if ($refused -and $check.ok) { 'PASS' } else { 'FAIL' })), $probe, $check.detail)
        if (-not ($refused -and $check.ok)) { exit 1 }
    }
    'Cleanup' {
        $err = [G248.Cred]::Delete($state.target)
        $blob = $null; $persist = 0
        $after = [G248.Cred]::Read($state.target, [ref]$blob, [ref]$persist)
        # 1168 = ERROR_NOT_FOUND
        $gone = $after -eq 1168
        Write-Log ("{0} deleted {1} (CredDelete error {2}); read afterwards error {3}" -f ($(if ($gone) { 'PASS' } else { 'FAIL' })), $state.target, $err, $after)
        Remove-Item -LiteralPath $statePath
        Write-Log "log kept at $($state.log)"
        if (-not $gone) { exit 1 }
    }
}
