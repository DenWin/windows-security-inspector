Set-StrictMode -Version 2.0

function Test-IsPowerShell7 { return $PSVersionTable.PSVersion.Major -ge 7 }
function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Get-PropertyValue { param($InputObject,[string]$Name,$Default=$null) if ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name]) { return $InputObject.$Name }; return $Default }
function Resolve-ExecutablePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded -match '^\s*"([^"]+)"') { return $matches[1] }
    if ($expanded -match '^\s*([^\s]+?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll))(?:\s|$)') { return $matches[1] }
    return $expanded
}
function New-SecurityFinding {
    param([string]$Category,[string]$Name,[string]$Description,[string]$Path,[string]$CommandLine,[string]$Publisher,[string]$SignatureStatus,[string]$HashSha256,[string]$Source,[hashtable]$Metadata)
    [pscustomobject]@{ Category=$Category; Name=$Name; Description=$Description; Path=$Path; CommandLine=$CommandLine; Publisher=$Publisher; SignatureStatus=$SignatureStatus; HashSha256=$HashSha256; Source=$Source; RiskScore=0; Severity='Informational'; Reasons=@(); RecommendedAction='Review if unexpected'; Metadata=if($Metadata){$Metadata}else{@{}} }
}
function Get-Severity { param([int]$Score) if($Score-ge80){'Critical'}elseif($Score-ge60){'High'}elseif($Score-ge40){'Medium'}elseif($Score-ge20){'Low'}else{'Informational'} }
function Test-PathPrefix { param([string]$Path,[string[]]$Prefixes) if(!$Path){return $false}; foreach($p in $Prefixes){if($p -and $Path.StartsWith([Environment]::ExpandEnvironmentVariables($p),[StringComparison]::OrdinalIgnoreCase)){return $true}}; return $false }
function Get-RiskAssessment {
    param([Parameter(Mandatory=$true)]$Finding,[Parameter(Mandatory=$true)]$Config,[Parameter(Mandatory=$true)]$Allowlist)
    $score=0; $reasons=New-Object System.Collections.ArrayList
    $path=[string]$Finding.Path; $publisher=[string]$Finding.Publisher; $sig=[string]$Finding.SignatureStatus; $category=[string]$Finding.Category
    function Add-Risk([int]$Points,[string]$Reason){$script:score+=$Points;[void]$reasons.Add($Reason)}
    if($category -in @('Startup','ScheduledTasks','Services','WmiPersistence','IFEO','AppInit')){Add-Risk 40 'Persistence or automatic execution'}
    if($path -match '(?i)\\AppData\\'){Add-Risk 20 'Located in AppData'}
    if($path -match '(?i)\\Temp\\'){Add-Risk 25 'Located in a temporary directory'}
    if($path -match '(?i)\\Downloads\\'){Add-Risk 20 'Located in Downloads'}
    if($sig -in @('NotSigned','UnknownError','HashMismatch')){Add-Risk 35 'Executable is unsigned or signature validation failed'}
    if([string]::IsNullOrWhiteSpace($publisher)){Add-Risk 25 'Publisher is unknown'}
    if($category -eq 'WmiPersistence'){Add-Risk 35 'WMI permanent event persistence'}
    if($category -eq 'Defender' -and (Get-PropertyValue $Finding.Metadata 'BroadExclusion' $false)){Add-Risk 30 'Broad Defender exclusion'}
    if($category -in @('Proxy','Hosts')){Add-Risk 20 'Network redirection configuration'}
    if(Test-PathPrefix $path @($env:windir,$env:ProgramFiles,${env:ProgramFiles(x86)})){Add-Risk -20 'Located under Windows or Program Files'}
    if($publisher -eq 'Microsoft Corporation' -and $sig -eq 'Valid'){Add-Risk -40 'Valid Microsoft signature'}
    if($Allowlist.TrustedPublishers -contains $publisher -and $sig -eq 'Valid'){Add-Risk -25 'Publisher is allowlisted'}
    if(Test-PathPrefix $path @($Allowlist.TrustedPaths)){Add-Risk -25 'Path is allowlisted'}
    if($Finding.HashSha256 -and $Allowlist.TrustedHashes -contains $Finding.HashSha256){Add-Risk -10 'Hash is allowlisted'}
    $score=[Math]::Max(0,[Math]::Min(100,$score)); $Finding.RiskScore=$score; $Finding.Severity=Get-Severity $score; $Finding.Reasons=@($reasons)
    if($score-ge60){$Finding.RecommendedAction='Investigate promptly; verify file origin, signature, and business need'}elseif($score-ge40){$Finding.RecommendedAction='Verify publisher and business need'}elseif($score-ge20){$Finding.RecommendedAction='Review if unexpected'}else{$Finding.RecommendedAction='No action unless unexpected'}
    return $Finding
}
function Get-FileInspection {
    param([string]$Path,[switch]$Hash)
    $result=@{Exists=$false;Publisher=$null;SignatureStatus=$null;HashSha256=$null;Size=$null;Created=$null;Modified=$null;Version=$null}
    if(!$Path -or !(Test-Path -LiteralPath $Path -PathType Leaf)){return $result}
    try{$f=Get-Item -LiteralPath $Path -ErrorAction Stop;$result.Exists=$true;$result.Size=$f.Length;$result.Created=$f.CreationTimeUtc;$result.Modified=$f.LastWriteTimeUtc;$result.Version=$f.VersionInfo.FileVersion}catch{}
    try{$s=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop;$result.SignatureStatus=[string]$s.Status;if($s.SignerCertificate){$result.Publisher=$s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}}catch{$result.SignatureStatus='Unavailable'}
    if($Hash){try{$result.HashSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash}catch{}}
    return $result
}
function Invoke-Collector { param([string]$Name,[scriptblock]$Script,[System.Collections.ArrayList]$Errors,[System.Collections.ArrayList]$Status)
    $sw=[Diagnostics.Stopwatch]::StartNew(); Write-Verbose "START: $Name"; Write-Progress -Activity 'Security PUP Forensics' -Status $Name
    try{$data=@(& $Script);$sw.Stop();[void]$Status.Add([pscustomobject]@{Name=$Name;State='Completed';Count=$data.Count;Duration=$sw.Elapsed.ToString()});Write-Verbose "COMPLETED: $Name | $($data.Count) records | $($sw.Elapsed.ToString())";return $data}
    catch{$sw.Stop();$state=if($_.Exception -is [UnauthorizedAccessException]){'PermissionDenied'}else{'Failed'};[void]$Errors.Add([pscustomobject]@{Section=$Name;State=$state;Message=$_.Exception.Message;ExceptionType=$_.Exception.GetType().FullName;Timestamp=(Get-Date).ToString('o');Stack=$_.ScriptStackTrace});[void]$Status.Add([pscustomobject]@{Name=$Name;State=$state;Count=0;Duration=$sw.Elapsed.ToString()});Write-Warning "FAILED: $Name | $($_.Exception.Message)";return @()}
}
function Get-InstalledPrograms {
    $keys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach($key in $keys){Get-ItemProperty $key -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName}|ForEach-Object{New-SecurityFinding 'InstalledPrograms' $_.DisplayName 'Installed software registry entry' $_.InstallLocation $_.UninstallString $_.Publisher $null $null $key @{DisplayVersion=$_.DisplayVersion;InstallDate=$_.InstallDate;Orphaned=([bool]($_.InstallLocation -and !(Test-Path $_.InstallLocation)))}}}
}
function Get-StartupFindings {
    $keys=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach($key in $keys){if(Test-Path $key){$p=Get-ItemProperty $key;foreach($prop in $p.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}){$cmd=[string]$prop.Value;$path=Resolve-ExecutablePath $cmd;New-SecurityFinding 'Startup' $prop.Name 'Executable runs at user logon' $path $cmd $null $null $null $key @{}}}}
    $folders=@([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'));foreach($folder in $folders){if(Test-Path $folder){Get-ChildItem $folder -File -ErrorAction SilentlyContinue|ForEach-Object{New-SecurityFinding 'Startup' $_.Name 'Startup folder item' $_.FullName $_.FullName $null $null $null $folder @{}}}}
}
function Get-ScheduledTaskFindings {
    if(!(Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)){throw 'ScheduledTasks module unavailable'}
    Get-ScheduledTask -ErrorAction Stop|ForEach-Object{$t=$_;foreach($a in @($t.Actions)){$exe=Get-PropertyValue $a 'Execute';$args=Get-PropertyValue $a 'Arguments';if($exe){New-SecurityFinding 'ScheduledTasks' $t.TaskName 'Scheduled task action' $exe (($exe+' '+$args).Trim()) $null $null $null $t.TaskPath @{Author=$t.Author;State=[string]$t.State;Principal=(Get-PropertyValue $t.Principal 'UserId');Triggers=@($t.Triggers)}}}}
}
function Get-ServiceFindings { Get-CimInstance Win32_Service -ErrorAction Stop|ForEach-Object{$path=Resolve-ExecutablePath $_.PathName;New-SecurityFinding 'Services' $_.DisplayName 'Windows service executable' $path $_.PathName $null $null $null $_.Name @{StartMode=$_.StartMode;State=$_.State;Account=$_.StartName}} }
function Get-DefenderFindings {
    if(!(Get-Command Get-MpPreference -ErrorAction SilentlyContinue)){throw 'Defender cmdlets unavailable'};$p=Get-MpPreference
    foreach($x in @($p.ExclusionPath)){New-SecurityFinding 'Defender' 'Defender path exclusion' 'Path excluded from Microsoft Defender scanning' $x $null 'Microsoft Corporation' $null $null 'Get-MpPreference' @{BroadExclusion=($x -match '^[A-Za-z]:\\?$|(?i)Users|ProgramData')}}
    New-SecurityFinding 'Defender' 'Defender configuration' 'Microsoft Defender preference state' $null $null 'Microsoft Corporation' $null $null 'Get-MpPreference' @{PUAProtection=$p.PUAProtection;DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring;MAPSReporting=$p.MAPSReporting}
}
function Get-ProxyFindings { $p=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue;if($p.ProxyEnable -or $p.AutoConfigURL){New-SecurityFinding 'Proxy' 'User proxy configuration' 'User proxy or PAC configuration is active' $null ([string]$p.ProxyServer) $null $null $null 'Internet Settings' @{ProxyEnable=$p.ProxyEnable;AutoConfigURL=$p.AutoConfigURL}} }
function Get-HostsFindings { $path=Join-Path $env:windir 'System32\drivers\etc\hosts';if(Test-Path $path){$lines=Get-Content $path|Where-Object{$_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost'};foreach($line in $lines){New-SecurityFinding 'Hosts' 'Hosts file entry' 'Non-default hosts file mapping' $path $line $null $null $null 'hosts' @{}}} }
function Get-WmiPersistenceFindings { $ns='root\subscription';foreach($class in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')){Get-CimInstance -Namespace $ns -ClassName $class -ErrorAction Stop|ForEach-Object{New-SecurityFinding 'WmiPersistence' (Get-PropertyValue $_ 'Name' $class) 'Permanent WMI event subscription object' $null (Get-PropertyValue $_ 'CommandLineTemplate') $null $null $null $class @{Raw=[string]$_}}} }
function Get-IfeoFindings { foreach($base in @('HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit')){if(Test-Path $base){Get-ChildItem $base|ForEach-Object{$p=Get-ItemProperty $_.PSPath;$d=Get-PropertyValue $p 'Debugger';$m=Get-PropertyValue $p 'MonitorProcess';if($d -or $m){New-SecurityFinding 'IFEO' $_.PSChildName 'IFEO or SilentProcessExit debugger configuration' (Resolve-ExecutablePath ($d+$m)) (($d+' '+$m).Trim()) $null $null $null $_.Name @{GlobalFlag=(Get-PropertyValue $p 'GlobalFlag')}}}}} }
function Get-AppInitFindings { foreach($view in @('HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')){if(Test-Path $view){$p=Get-ItemProperty $view;if($p.LoadAppInit_DLLs -or $p.AppInit_DLLs){New-SecurityFinding 'AppInit' 'AppInit DLL configuration' 'AppInit DLL injection configuration' ([string]$p.AppInit_DLLs) ([string]$p.AppInit_DLLs) $null $null $null $view @{LoadAppInit_DLLs=$p.LoadAppInit_DLLs;RequireSignedAppInit_DLLs=$p.RequireSignedAppInit_DLLs}}}} }
function Get-FirewallFindings { if(!(Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)){throw 'NetSecurity module unavailable'};Get-NetFirewallRule -Enabled True -ErrorAction Stop|Where-Object{$_.PolicyStoreSourceType -ne 'SystemDefaults'}|ForEach-Object{New-SecurityFinding 'Firewall' $_.DisplayName 'Enabled non-default firewall rule' $null $null $null $null $null $_.Name @{Direction=[string]$_.Direction;Action=[string]$_.Action;Profile=[string]$_.Profile}} }
function Get-CertificateFindings { foreach($store in @('Cert:\CurrentUser\Root','Cert:\LocalMachine\Root')){Get-ChildItem $store -ErrorAction SilentlyContinue|ForEach-Object{if($_.Subject -eq $_.Issuer -or $store -like '*CurrentUser*'){New-SecurityFinding 'Certificates' $_.Subject 'Root certificate requiring provenance review' $null $null $null $null $_.Thumbprint $store @{Issuer=$_.Issuer;NotBefore=$_.NotBefore;NotAfter=$_.NotAfter;SelfSigned=($_.Subject -eq $_.Issuer)}}}} }
function Get-EnvironmentFindings { foreach($scope in @('Machine','User')){$path=[Environment]::GetEnvironmentVariable('Path',$scope);$seen=@{};foreach($entry in @($path -split ';'|Where-Object{$_})){ $e=[Environment]::ExpandEnvironmentVariables($entry.Trim());$duplicate=$seen.ContainsKey($e.ToLowerInvariant());$seen[$e.ToLowerInvariant()]=$true;if($duplicate -or !(Test-Path $e) -or $e -match '(?i)AppData|Temp|Downloads'){New-SecurityFinding 'Environment' "$scope PATH entry" 'PATH entry is duplicate, missing, or user-writable' $e $null $null $null $null "$scope PATH" @{Duplicate=$duplicate;Missing=!(Test-Path $e)}}}} }
function Get-PortableApplications { param([string[]]$Paths) foreach($root in $Paths){if(Test-Path $root){Get-ChildItem $root -File -Recurse -ErrorAction SilentlyContinue|Where-Object{$_.Extension -in @('.exe','.com','.bat','.cmd','.ps1','.vbs','.js') -and $_.FullName -notmatch '(?i)node_modules|\.git|cache|packages'}|Select-Object -First 2000|ForEach-Object{New-SecurityFinding 'PortableApplications' $_.BaseName 'Executable in a common user location' $_.FullName $_.FullName $null $null $null $root @{}}}} }
function Get-BrowserExtensions {
    $roots=@(@{Browser='Chrome';Path="$env:LOCALAPPDATA\Google\Chrome\User Data"},@{Browser='Edge';Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data"})
    foreach($r in $roots){if(Test-Path $r.Path){Get-ChildItem $r.Path -Directory -Filter Extensions -Recurse -ErrorAction SilentlyContinue|ForEach-Object{Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue|ForEach-Object{$id=$_.Name;$version=Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue|Sort-Object Name -Descending|Select-Object -First 1;$manifest=if($version){Join-Path $version.FullName 'manifest.json'}else{$null};$name=$id;$meta=@{};if($manifest -and (Test-Path $manifest)){try{$m=Get-Content $manifest -Raw|ConvertFrom-Json;$name=Get-PropertyValue $m 'name' $id;$meta.Version=Get-PropertyValue $m 'version';$meta.Permissions=@(Get-PropertyValue $m 'permissions' @());$meta.UpdateUrl=Get-PropertyValue $m 'update_url'}catch{}};New-SecurityFinding 'BrowserExtensions' $name "$($r.Browser) browser extension" $_.FullName $null $null $null $null $id $meta}}}}
    $ff="$env:APPDATA\Mozilla\Firefox\Profiles";if(Test-Path $ff){Get-ChildItem $ff -Filter extensions.json -Recurse -ErrorAction SilentlyContinue|ForEach-Object{try{$j=Get-Content $_.FullName -Raw|ConvertFrom-Json;foreach($a in @($j.addons)){New-SecurityFinding 'BrowserExtensions' (Get-PropertyValue $a.defaultLocale 'name' $a.id) 'Firefox browser extension' $a.path $null $null $null $null $a.id @{Version=$a.version;Active=$a.active;SignedState=$a.signedState}}}catch{}}}
}
function Write-Reports { param($Report,[string]$Directory,[switch]$NoHtml)
    $full=Join-Path $Directory 'Security-PUP-Forensics.json';$summary=Join-Path $Directory 'Security-PUP-Summary.json';$md=Join-Path $Directory 'Security-PUP-Report.md'
    $Report|ConvertTo-Json -Depth 12|Set-Content $full -Encoding UTF8
    $sum=[pscustomobject]@{Metadata=$Report.Metadata;CountsBySeverity=$Report.Findings|Group-Object Severity|ForEach-Object{[pscustomobject]@{Severity=$_.Name;Count=$_.Count}};CountsByCategory=$Report.Findings|Group-Object Category|ForEach-Object{[pscustomobject]@{Category=$_.Name;Count=$_.Count}};TopFindings=@($Report.Findings|Sort-Object RiskScore -Descending|Select-Object -First 20);FailedCollectors=@($Report.CollectorStatus|Where-Object{$_.State-ne'Completed'});Runtime=$Report.Metadata.Duration}
    $sum|ConvertTo-Json -Depth 8|Set-Content $summary -Encoding UTF8
    $lines=New-Object System.Collections.ArrayList;[void]$lines.Add('# Security PUP Forensics Report');[void]$lines.Add('');[void]$lines.Add('## Executive Summary');[void]$lines.Add("- Mode: $($Report.Metadata.Mode)");[void]$lines.Add("- Findings: $($Report.Findings.Count)");[void]$lines.Add("- PowerShell: $($Report.Metadata.PowerShellVersion)");[void]$lines.Add("- Elevated: $($Report.Metadata.IsAdministrator)");
    foreach($sev in @('Critical','High','Medium','Low','Informational')){[void]$lines.Add('');[void]$lines.Add("## $sev Findings");$items=@($Report.Findings|Where-Object{$_.Severity-eq$sev}|Sort-Object RiskScore -Descending);if(!$items){[void]$lines.Add('_None._')}else{foreach($f in $items){[void]$lines.Add("### [$($f.RiskScore)] $($f.Category): $($f.Name)");[void]$lines.Add("- Path: ``$($f.Path)``");[void]$lines.Add("- Source: $($f.Source)");[void]$lines.Add("- Reasons: $([string]::Join('; ',@($f.Reasons)))");[void]$lines.Add("- Action: $($f.RecommendedAction)")}}}
    [void]$lines.Add('');[void]$lines.Add('## Errors and Limitations');foreach($e in @($Report.Errors)){[void]$lines.Add("- $($e.Section): $($e.State) - $($e.Message)")};$lines|Set-Content $md -Encoding UTF8
    if(!$NoHtml){$html='<html><body><pre>'+[Net.WebUtility]::HtmlEncode(($lines -join [Environment]::NewLine))+'</pre></body></html>';Set-Content (Join-Path $Directory 'Security-PUP-Report.html') $html -Encoding UTF8}
}
function Invoke-SecurityPupForensics {
    [CmdletBinding()]param([ValidateSet('Fast','Standard','Deep')][string]$Mode='Standard',[string]$OutputDirectory=(Join-Path $PSScriptRoot 'Output'),[string]$AllowlistPath=(Join-Path $PSScriptRoot 'Config\default-allowlist.json'),[string]$ConfigPath=(Join-Path $PSScriptRoot 'Config\default-config.json'),[string]$VirusTotalApiKey,[switch]$NoHtml,[switch]$NoHashes)
    $started=Get-Date;$stamp=$started.ToString('yyyy-MM-dd_HH-mm-ss');$dir=Join-Path $OutputDirectory "Security-PUP-Forensics_$stamp";New-Item $dir -ItemType Directory -Force|Out-Null;$log=Join-Path $dir 'Execution.log';Start-Transcript -Path $log -Force|Out-Null
    try{$config=Get-Content $ConfigPath -Raw|ConvertFrom-Json;$allow=Get-Content $AllowlistPath -Raw|ConvertFrom-Json;$errors=New-Object System.Collections.ArrayList;$status=New-Object System.Collections.ArrayList;$raw=@{};$findings=New-Object System.Collections.ArrayList
        $collectors=[ordered]@{InstalledPrograms={Get-InstalledPrograms};Startup={Get-StartupFindings};ScheduledTasks={Get-ScheduledTaskFindings};Services={Get-ServiceFindings};BrowserExtensions={Get-BrowserExtensions};Defender={Get-DefenderFindings};Proxy={Get-ProxyFindings};Hosts={Get-HostsFindings};Firewall={Get-FirewallFindings};WmiPersistence={Get-WmiPersistenceFindings};IFEO={Get-IfeoFindings};AppInit={Get-AppInitFindings}}
        if($Mode -in @('Standard','Deep')){$collectors.Certificates={Get-CertificateFindings};$collectors.Environment={Get-EnvironmentFindings};$paths=@([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('MyDocuments'),(Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:LOCALAPPDATA 'Programs'))+@($config.PortableApplicationPaths);$collectors.PortableApplications={Get-PortableApplications $paths}}
        foreach($name in $collectors.Keys){$items=@(Invoke-Collector $name $collectors[$name] $errors $status);$raw[$name]=$items;foreach($f in $items){$inspection=Get-FileInspection $f.Path -Hash:($Mode-eq'Deep' -and !$NoHashes);if($inspection.Exists){$f.Publisher=$inspection.Publisher;$f.SignatureStatus=$inspection.SignatureStatus;$f.HashSha256=$inspection.HashSha256;$f.Metadata.FileInspection=$inspection};[void]$findings.Add((Get-RiskAssessment $f $config $allow))}}
        $ended=Get-Date;$report=[pscustomobject]@{Metadata=[pscustomobject]@{Tool='Windows Security Inspector';Version='0.1.0';Mode=$Mode;Started=$started.ToString('o');Completed=$ended.ToString('o');Duration=($ended-$started).ToString();ComputerName=$env:COMPUTERNAME;UserName=$env:USERNAME;PowerShellVersion=$PSVersionTable.PSVersion.ToString();PSEdition=(Get-PropertyValue $PSVersionTable 'PSEdition' 'Desktop');IsAdministrator=Test-IsAdministrator;VirusTotalEnabled=[bool]$VirusTotalApiKey};Configuration=$config;CollectorResults=$raw;Findings=@($findings|Sort-Object RiskScore -Descending);Errors=@($errors);CollectorStatus=@($status)};Write-Reports $report $dir -NoHtml:$NoHtml;return $report
    }finally{Write-Progress -Activity 'Security PUP Forensics' -Completed;try{Stop-Transcript|Out-Null}catch{}}
}
Export-ModuleMember -Function Invoke-SecurityPupForensics,Get-RiskAssessment,New-SecurityFinding
