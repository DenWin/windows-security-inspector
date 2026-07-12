[CmdletBinding()]
param(
    [ValidateSet('Fast','Standard','Deep')][string]$Mode = 'Standard',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'Output'),
    [string]$AllowlistPath = (Join-Path $PSScriptRoot 'Config\default-allowlist.json'),
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'Config\default-config.json'),
    [string]$VirusTotalApiKey,
    [switch]$NoHtml,
    [switch]$NoHashes
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SecurityPupForensics.psd1') -Force

Invoke-SecurityPupForensics -Mode $Mode -OutputDirectory $OutputDirectory -AllowlistPath $AllowlistPath -ConfigPath $ConfigPath -VirusTotalApiKey $VirusTotalApiKey -NoHtml:$NoHtml -NoHashes:$NoHashes -Verbose:$VerbosePreference
