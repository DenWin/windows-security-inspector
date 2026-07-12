# Architecture

`Invoke-SecurityPupForensics.ps1` is the stable CLI entry point. It imports `SecurityPupForensics.psd1`, whose root module contains compatibility helpers, collectors, file inspection, risk scoring, failure isolation, and report writers.

Collectors return normalized finding objects and never formatted display text. `Invoke-Collector` isolates failures and records state, duration, record count, exception type, timestamp, and stack information. The orchestrator enriches executable targets with Authenticode and optional SHA-256 data, applies the rule-based risk engine, and writes deterministic report formats.

The implementation intentionally avoids PS7-only syntax and generic `List<T>` usage. Windows-specific cmdlets are capability-checked. Missing modules become recorded collector failures rather than terminating the scan.

## Data flow

1. Load configuration and allowlist.
2. Select collectors for Fast, Standard, or Deep mode.
3. Execute each collector independently.
4. Inspect executable targets without executing them.
5. Apply transparent risk rules and allowlist reductions.
6. Sort findings by risk.
7. Write full JSON, summary JSON, Markdown, optional HTML, and transcript log.

## Extension model

New collectors should return objects created through `New-SecurityFinding`. They must be read-only, null-safe, and suitable for invocation through `Invoke-Collector`.
