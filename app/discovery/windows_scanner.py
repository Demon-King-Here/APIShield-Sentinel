import json
import platform
import subprocess
import ipaddress
import os
from pathlib import Path
import psutil
from .process_inspector import process_info
from .classification import classify
from app.database.db import now

# Fixed, read-only script. No dashboard input is interpolated into commands.
POWERSHELL_SCRIPT = r'''
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$services = @{}
try { Get-CimInstance Win32_Service | ForEach-Object {
  $key = [int]$_.ProcessId
  if (-not $services.ContainsKey($key)) { $services[$key] = @() }
  $services[$key] += $_.Name
} } catch { }
$processes = @{}
Get-Process | ForEach-Object { $processes[[int]$_.Id] = $_ }
$rows = @(Get-NetTCPConnection -State Listen | ForEach-Object {
  $owner = [int]$_.OwningProcess
  $proc = $processes[$owner]
  $exe = $null
  try { $exe = $proc.Path } catch { }
  [PSCustomObject]@{
    LocalAddress = $_.LocalAddress; LocalPort = [int]$_.LocalPort
    OwningProcess = $owner; ProcessName = $proc.ProcessName
    ExecutablePath = $exe; Services = @($services[$owner])
  }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
'''


def parse_windows_output(output):
    records = json.loads(output.lstrip('\ufeff').strip() or '[]')
    if isinstance(records, dict):
        records = [records]
    listeners = []
    for row in records:
        try:
            address = str(row['LocalAddress'])
            ipaddress.ip_address(address.split('%')[0])
            port = int(row['LocalPort'])
            if not 1 <= port <= 65535:
                continue
            listeners.append(dict(port=port, local_address=address, **process_info(row)))
        except (KeyError, ValueError, TypeError):
            continue
    return listeners


def scan(services):
    limitations = []
    if platform.system() == 'Windows':
        try:
            powershell=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
            result = subprocess.run([str(powershell),'-NoLogo','-NoProfile','-NonInteractive','-Command', POWERSHELL_SCRIPT],
                                    capture_output=True, timeout=30, encoding='utf-8', errors='replace', check=True,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            listeners = parse_windows_output(result.stdout)
            source = 'Windows Get-NetTCPConnection / Get-Process / Win32_Service'
        except (OSError, subprocess.SubprocessError, ValueError):
            return dict(timestamp=now(), source='Windows discovery failed', listeners=[],
                        limitations=['Windows listener discovery unavailable or permission denied. Existing snapshot is retained. No firewall changes were attempted.'], success=False)
    else:
        source = 'Non-Windows psutil development fallback'
        limitations.append('Windows discovery was not performed. Fallback may omit protected processes.')
        listeners = []
        try:
            for conn in psutil.net_connections(kind='tcp'):
                if conn.status != psutil.CONN_LISTEN:
                    continue
                row = {'pid':conn.pid}
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    if proc:
                        row.update(ProcessName=proc.name(), ExecutablePath=proc.exe())
                except (psutil.Error, OSError):
                    pass
                listeners.append(dict(port=conn.laddr.port, local_address=conn.laddr.ip, **process_info(row)))
        except (psutil.Error, OSError):
            limitations.append('Listener enumeration unavailable or permission denied.')
    return dict(timestamp=now(), source=source, listeners=[classify(l, services) for l in listeners],
                limitations=limitations + ['No external reachability test performed. Missing process paths may require additional read permissions.'], success=True)
