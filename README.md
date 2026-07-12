# Windows Security Inspector

Read-only PowerShell security inventory and PUP-forensics tool for Windows PowerShell 5.1 and PowerShell 7.x.

## Purpose

The tool inventories installed software, persistence mechanisms, browser extensions, Defender exclusions, firewall rules, proxy/hosts changes, certificates, environment manipulation, and executable metadata. Findings receive a transparent 0-100 risk score with reasons and a recommended action.

It does **not** prove that software is malicious. Unsigned software is only one factor. Validate findings before remediation.

## Requirements

- Windows 10/11 or Windows Server with Windows PowerShell 5.1 or PowerShell 7
- Administrator rights are recommended but not required
- Default execution is fully read-only

## Usage

```powershell
.\Invoke-SecurityPupForensics.ps1
.\Invoke-SecurityPupForensics.ps1 -Mode Fast
.\Invoke-SecurityPupForensics.ps1 -Mode Standard
.\Invoke-SecurityPupForensics.ps1 -Mode Deep
.\Invoke-SecurityPupForensics.ps1 -OutputDirectory C:\Temp\SecurityAudit
```

Use a custom allowlist:

```powershell
.\Invoke-SecurityPupForensics.ps1 -AllowlistPath C:\Config\allowlist.json
```

Deep mode hashes only executable targets discovered by collectors. It does not recursively hash the entire system. VirusTotal is opt-in; only hashes may be submitted, never files. The initial implementation records opt-in state but does not yet send API requests.

## Scan modes

- **Fast:** core inventory and persistence/security configuration.
- **Standard:** Fast plus portable applications, certificates, and PATH analysis.
- **Deep:** Standard plus SHA-256 hashing of discovered executable targets.

## Output

Each run creates `Output\Security-PUP-Forensics_YYYY-MM-DD_HH-mm-ss\` containing:

- `Security-PUP-Forensics.json`
- `Security-PUP-Summary.json`
- `Security-PUP-Report.md`
- `Security-PUP-Report.html` unless `-NoHtml`
- `Execution.log`

## Risk scoring

Severity mapping:

| Score | Severity |
|---:|---|
| 0-19 | Informational |
| 20-39 | Low |
| 40-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

Every finding contains its reasons. Rules are represented in `Config/default-config.json`; the current engine implements the baseline rule set directly for PS5.1 compatibility.

## False positives

Signed software, business-specific agents, portable tools, developer runtimes, and legitimate administrative persistence may still be reported. Add verified publishers, paths, or hashes to an allowlist rather than deleting findings.

## Privacy and security

The tool does not upload data, execute discovered binaries, modify system settings, uninstall software, delete files, disable services, or change Defender/firewall configuration.

## Tests

```powershell
Invoke-Pester .\Tests
```

## Contributing

Keep shared code compatible with PowerShell 5.1, use approved verbs, return structured objects, isolate collector failures, and add Pester coverage for behavior changes.
