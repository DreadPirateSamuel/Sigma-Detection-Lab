# Live positive controls for four of the six rules. Run as Administrator.
#
# Every action below is a harmless administrative command on your own machine,
# and each one is undone before the script ends:
#   1. PowerShell started with -EncodedCommand; the payload only prints a word.
#   2. A scheduled task created with schtasks /create /tr, then deleted.
#   3. An HKCU Run value containing "cmd.exe", then deleted.
#   4. A throwaway event log created, cleared (System event 104), then removed.
#
# The resulting events stay in the live-host log and index. Record the printed
# UTC start time, and report later live-host matches from these runs as
# positive controls, never as benign-baseline false positives.
#
# No real log is cleared and no attack tool runs. LSASS access and WMI event
# subscriptions are deliberately NOT exercised here: producing them on a daily
# machine means credential-dumping-like or persistence-like behaviour, so those
# two rules stay validated by the recorded samples only.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$name = 'SocLabPositiveControl'
$logName = 'SocLabControl'
$runKey = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'STOPPED: run this from Administrator PowerShell.'
    exit 1
}

$startUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Host "Start (UTC): $startUtc"

# 1. Encoded PowerShell (rule: powershell_encoded_command)
$payload = "Write-Output 'soc-lab-positive-control'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
$printed = & powershell.exe -NoProfile -EncodedCommand $encoded
Write-Host "1/4 Encoded PowerShell ran; it printed: $printed"

# 2. Scheduled task creation (rule: schtasks_create_task)
try {
    & schtasks.exe /create /tn $name /tr 'cmd.exe /c echo soc-lab-positive-control' /sc once /st 23:59 /f | Out-Null
    Write-Host "2/4 Scheduled task created (schtasks exit code $LASTEXITCODE)."
} finally {
    & schtasks.exe /delete /tn $name /f | Out-Null
    Write-Host '    Scheduled task deleted.'
}

# 3. Run-key value (rule: run_key_suspicious_value)
try {
    & reg.exe add $runKey /v $name /t REG_SZ /d 'cmd.exe /c echo soc-lab-positive-control' /f | Out-Null
    Write-Host "3/4 Run value written (reg exit code $LASTEXITCODE)."
} finally {
    & reg.exe delete $runKey /v $name /f | Out-Null
    Write-Host '    Run value deleted.'
}

# 4. Log clearing on a throwaway log (rule: windows_event_log_cleared, System 104)
try {
    if (-not [Diagnostics.EventLog]::Exists($logName)) {
        New-EventLog -LogName $logName -Source $logName
    }
    Write-EventLog -LogName $logName -Source $logName -EventId 1 -Message 'soc-lab-positive-control'
    & wevtutil.exe cl $logName
    Write-Host "4/4 Throwaway log '$logName' cleared (wevtutil exit code $LASTEXITCODE)."
} finally {
    if ([Diagnostics.EventLog]::Exists($logName)) { Remove-EventLog -LogName $logName }
    Write-Host '    Throwaway log removed.'
}

Write-Host ''
Write-Host 'CONTROLS COMPLETE. Wait 60 seconds, then run scripts/check-live-controls.py in WSL.'
Write-Host "Start (UTC) for the checker: $startUtc"
