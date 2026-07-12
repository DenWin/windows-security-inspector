BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\SecurityPupForensics.psd1') -Force
    $config = Get-Content (Join-Path $PSScriptRoot '..\Config\default-config.json') -Raw | ConvertFrom-Json
    $allow = Get-Content (Join-Path $PSScriptRoot '..\Config\default-allowlist.json') -Raw | ConvertFrom-Json
}

Describe 'Module compatibility and schema' {
    It 'imports successfully' { Get-Module SecurityPupForensics | Should -Not -BeNullOrEmpty }
    It 'creates stable finding keys' {
        $f = New-SecurityFinding -Category Startup -Name Test -Description Test -Path 'C:\Temp\x.exe' -CommandLine 'x.exe' -Publisher $null -SignatureStatus NotSigned -HashSha256 $null -Source Test -Metadata @{}
        @('Category','Name','Description','Path','CommandLine','Publisher','SignatureStatus','HashSha256','Source','RiskScore','Severity','Reasons','RecommendedAction','Metadata') | ForEach-Object { $f.PSObject.Properties.Name | Should -Contain $_ }
    }
}

Describe 'Risk engine' {
    It 'maps high-risk startup artifact' {
        $f = New-SecurityFinding -Category Startup -Name Test -Description Test -Path 'C:\Users\x\AppData\Local\x.exe' -CommandLine 'x.exe' -Publisher $null -SignatureStatus NotSigned -HashSha256 $null -Source Test -Metadata @{}
        $r = Get-RiskAssessment -Finding $f -Config $config -Allowlist $allow
        $r.RiskScore | Should -BeGreaterOrEqual 80
        $r.Severity | Should -Be 'Critical'
        $r.Reasons.Count | Should -BeGreaterThan 0
    }
    It 'does not classify unsigned software solely as malicious' {
        $f = New-SecurityFinding -Category InstalledPrograms -Name Test -Description Test -Path 'C:\Program Files\Test\x.exe' -CommandLine $null -Publisher 'Example' -SignatureStatus NotSigned -HashSha256 $null -Source Test -Metadata @{}
        $r = Get-RiskAssessment -Finding $f -Config $config -Allowlist $allow
        $r.RiskScore | Should -BeLessThan 80
    }
    It 'reduces score for allowlisted signed publisher' {
        $f = New-SecurityFinding -Category InstalledPrograms -Name Test -Description Test -Path 'C:\Program Files\Google\x.exe' -CommandLine $null -Publisher 'Google LLC' -SignatureStatus Valid -HashSha256 $null -Source Test -Metadata @{}
        $r = Get-RiskAssessment -Finding $f -Config $config -Allowlist $allow
        $r.Severity | Should -Be 'Informational'
    }
}

Describe 'Manifest' {
    It 'is valid PowerShell data' { Test-ModuleManifest (Join-Path $PSScriptRoot '..\SecurityPupForensics.psd1') | Should -Not -BeNullOrEmpty }
}
