# Sample-context review and scope labels

This is a review of recorded observable signals and public filename/tactic
context. It does **not** independently label every sample/event for an
ATT&CK technique or adjudicate malicious intent. ATT&CK mapping describes
the rule behavior; precursor-file denominators describe available signals.
See the evidence JSON for all file identities and feature groups.

## Representative mapped signals

| Rule behavior | Mapping | Recorded context supporting the observable signal | Limit |
| --- | --- | --- | --- |
| Selected-mask LSASS access | T1003.001 | Credential Access / sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx; mimikatz.exe, mask 0x1010 | Access rights do not prove a successful dump; some matches occur in other scenario folders |
| Encoded PowerShell | T1059.001 | Credential Access / discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx; PowerShell process with selected encoded switch | Encoded execution can be adjacent to IIS discovery; it is not a malicious-PowerShell ground-truth benchmark |
| Selected Run/RunOnce data | T1547.001 | AutomatedTestingTools / PanacheSysmon_vs_AtomicRedTeam01.evtx; RunOnce value with PowerShell indicator | A file can contain both matching and out-of-scope Run writes |
| Schtasks creation | T1053.005 | rundll32_cmd_schtask.evtx and sysmon_1_11_exec_as_system_via_schedtask.evtx; /create with /xml | Creation attempts/visibility do not prove successful registration or malicious intent |
| WMI binding | T1546.003 | Persistence / sysmon_20_21_1_CommandLineEventConsumer.evtx and wmighost_sysmon_20_21_1.evtx; Sysmon 21 | Legitimate permanent subscriptions use the same mechanism; no baseline eligible events |
| Scoped log clearing | T1685.005 | Defense Evasion / DE_104_system_log_cleared.evtx and DE_1102_security_log_cleared.evtx | Historical folder name is retained; the current taxonomy maps to Defense Impairment |

## File-level precursor coverage and unmatched events

### LSASS Access With Selected Memory Read Access Masks

14/14 precursor files have a match. 2 reviewed precursor events remain outside the predicate.

Every precursor file has a match; this does not imply every event in it matches.

### PowerShell Process With Encoded Command Argument

1/12 precursor files have a match. 15 reviewed precursor events remain outside the predicate.

Files with precursor signals but no rule match:

- AutomatedTestingTools / PanacheSysmon_vs_AtomicRedTeam01.evtx
- AutomatedTestingTools / panache_sysmon_vs_EDRTestingScript.evtx
- Credential Access / babyshark_mimikatz_powershell.evtx
- Execution / execution_evasion_visual_studio_prebuild_event.evtx
- Lateral Movement / ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx
- Lateral Movement / LM_sysmon_3_12_13_1_SharpRDP.evtx
- Lateral Movement / LM_sysmon_psexec_smb_meterpreter.evtx
- Lateral Movement / lm_sysmon_18_remshell_over_namedpipe.evtx
- Privilege Escalation / Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx
- Privilege Escalation / privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx
- Privilege Escalation / sysmon_1_7_elevate_uacbypass_sysprep.evtx

### Run Key Value Referencing a Script Host or User Writable Location

4/6 precursor files have a match. 3 reviewed precursor events remain outside the predicate.

Files with precursor signals but no rule match:

- AutomatedTestingTools / sideloading_injection_persistence_run_key.evtx
- Persistence / evasion_persis_hidden_run_keyvalue_sysmon_13.evtx

### Scheduled Task Creation Through Schtasks

6/8 precursor files have a match. 4 reviewed precursor events remain outside the predicate.

Files with precursor signals but no rule match:

- Persistence / persistence_sysmon_11_13_1_shime_appfix.evtx
- Privilege Escalation / Sysmon_UACME_34.evtx

### Windows Security or System Event Log Clearing

26/26 precursor files have a match. 0 reviewed precursor events remain outside the predicate.

Every precursor file has a match; this does not imply every event in it matches.

### WMI Permanent Event Consumer Filter Binding

3/3 precursor files have a match. 0 reviewed precursor events remain outside the predicate.

Every precursor file has a match; this does not imply every event in it matches.

The LSASS unmatched events use query-only 0x1000 in a file that also contains
selected-mask matches. PowerShell unmatched starts lack the reviewed encoded
switch. Schtasks unmatched events are /run or /delete, outside creation scope.
Run-key unmatched writes lack the selected data indicators. These are bounded
scope observations, not technique-wide false-negative counts.

## Public matches retained for investigation

| Rule | Public events | Reviewed fixed context |
| --- | ---: | --- |
| LSASS | 86 Win11 | msiexec 55; Dropbox/update 16; MRT 9; csrss/wininit 4; OfficeClickToRun/WmiPrvSE 2 |
| Schtasks | 9 Win11 | /xml: integrator parent 4, OfficeClickToRun parent 4; /tr: TeamViewer parent 1 |
| Run/RunOnce | 2 Win11 | target.exe writer, AppData/Temp; cmd.exe/Python installer references |
| Log clearing | 1 Win10 | System 104, Microsoft-Windows-Eventlog |
| Encoded PowerShell | 0 | Only eight public Win11 PowerShell starts; representation is limited |
| WMI binding | 0 | No eligible public WMI binding records; specificity is untested |

Executable names/location classes suggest context but do not verify signatures,
trusted paths, ownership, or intent. No basename exclusions were added. Baseline
hits remain visible instead of being optimized away to obtain zero counts.

## Ground-truth boundary

The project reports observable-file coverage only. Independently labeled,
procedure-specific samples and a held-out evaluation set are future work.
No maliciousness verdict is assigned from a sample filename, folder, or
executable basename. All 278 indexed source identities, including unmatched
ones, are preserved in coverage/file-coverage.json for further review.
