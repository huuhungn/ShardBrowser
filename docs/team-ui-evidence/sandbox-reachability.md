# Sandbox reachability (spike S0)

**Result:** PASS. Windows Sandbox reaches a team server on the host through a
`portproxy` to its own loopback. Step M.0b of the two-machine run uses this
method; the HTTPS fallback is not needed.

**Use disposable test credentials only.** This path carries the test password
and the session tokens in plaintext over the virtual network between the host
and the Sandbox.

## Run

- Date: 2026-11-05.
- Host: Windows 11 Pro, build 10.0.26300.9711. Sandbox: `[Environment]::OSVersion`
  reports 10.0.26100.0.
- Server: `shardx-team-server` built from main 07260ecc, run with a throwaway
  data directory, identity and tenant, bound to `0.0.0.0:8080`.
- Host firewall: one inbound rule for that server binary, TCP 8080, remote
  address `LocalSubnet` only. Removed after the run.

## Commands (redacted)

On the host, elevated, before the run:

```powershell
New-NetFirewallRule -DisplayName 'shardx-s0 8080' -Direction Inbound -Program <server exe> `
  -Protocol TCP -LocalPort 8080 -RemoteAddress LocalSubnet -Action Allow -Profile Any
```

The `.wsb` maps a read-only `in` folder and a writable `out` folder, enables
networking, disables the vGPU, and runs `in\probe.ps1` as its `LogonCommand`.
The probe records only status codes:

```powershell
$hostIp = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
Start-Service iphlpsvc
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=8080 connectaddress=$hostIp connectport=8080
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/health
Invoke-WebRequest -UseBasicParsing -Method Post -ContentType 'application/json' -Body <throwaway login> http://127.0.0.1:8080/v2/auth/login
```

After the run: the Sandbox was closed, the server stopped, and the firewall rule
removed (`Remove-NetFirewallRule -DisplayName 'shardx-s0 8080'`).

## Statuses

| Request from the Sandbox | Status |
|---|---|
| `GET /health` | 200 |
| `POST /v2/auth/login` | 201 |

A successful `POST /v2/auth/login` answers `201 Created`, because it opens a
new session (`server/src/routes/v2_auth.rs`, `login`). The same login from the
host also answered 201.
