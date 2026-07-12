@{
    RootModule = 'SecurityPupForensics.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'f669ecda-91d9-48a4-a02d-14903d34c941'
    Author = 'Dennis Winter'
    CompanyName = 'DenWin'
    Copyright = '(c) 2026 Dennis Winter. MIT License.'
    Description = 'Read-only Windows security inventory and PUP-forensics toolkit.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-SecurityPupForensics','Get-RiskAssessment','New-SecurityFinding')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('Windows','Security','Forensics','PUP','Inventory') } }
}
