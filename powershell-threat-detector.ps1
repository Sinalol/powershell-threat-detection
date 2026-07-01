param(
    [int]$HoursBack = 24,
    [string]$OutputPath = ".\powershell-threat-report.csv"
)

$startTime = (Get-Date).AddHours(-$HoursBack)

$patterns = @(
    @{
        Name        = "Encoded PowerShell command"
        Severity    = "High"
        Pattern     = "(?i)(-enc|-encodedcommand|frombase64string)"
        Mitre       = "T1059.001"
        Description = "Possible encoded PowerShell execution"
    },
    @{
        Name        = "Execution policy bypass"
        Severity    = "Medium"
        Pattern     = "(?i)(executionpolicy\s+bypass|-ep\s+bypass)"
        Mitre       = "T1059.001"
        Description = "PowerShell execution policy bypass detected"
    },
    @{
        Name        = "Hidden PowerShell window"
        Severity    = "Medium"
        Pattern     = "(?i)(windowstyle\s+hidden|-w\s+hidden)"
        Mitre       = "T1059.001"
        Description = "PowerShell launched with a hidden window"
    },
    @{
        Name        = "Suspicious download command"
        Severity    = "High"
        Pattern     = "(?i)(invoke-webrequest|iwr|wget|downloadstring|webclient)"
        Mitre       = "T1105"
        Description = "Possible remote file download"
    },
    @{
        Name        = "Invoke-Expression use"
        Severity    = "High"
        Pattern     = "(?i)(invoke-expression|\biex\b)"
        Mitre       = "T1059.001"
        Description = "Dynamic PowerShell command execution"
    },
    @{
        Name        = "Credential-related command"
        Severity    = "High"
        Pattern     = "(?i)(mimikatz|sekurlsa|credential|lsass|sam)"
        Mitre       = "T1003"
        Description = "Possible credential access activity"
    },
    @{
        Name        = "Persistence-related command"
        Severity    = "Medium"
        Pattern     = "(?i)(new-scheduledtask|register-scheduledtask|new-service|set-itemproperty.*run)"
        Mitre       = "T1053,T1543,T1060"
        Description = "Possible persistence activity"
    }
)

Write-Host "Analyzing PowerShell operational logs from the last $HoursBack hours..."
Write-Host ""

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4103, 4104
        StartTime = $startTime
    } -ErrorAction Stop
}
catch {
    Write-Error "Unable to read PowerShell operational logs. Run PowerShell as Administrator and make sure PowerShell logging is enabled."
    exit 1
}

$findings = foreach ($event in $events) {
    $message = $event.Message

    foreach ($rule in $patterns) {
        if ($message -match $rule.Pattern) {
            [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                EventID     = $event.Id
                RuleName    = $rule.Name
                Severity    = $rule.Severity
                MITRE       = $rule.Mitre
                Description = $rule.Description
                Computer    = $event.MachineName
                User        = $event.UserId
                Evidence    = ($message -replace "`r|`n", " ").Substring(
                    0,
                    [Math]::Min(250, ($message -replace "`r|`n", " ").Length)
                )
            }
        }
    }
}

if (-not $findings) {
    Write-Host "No suspicious PowerShell activity was detected."
    exit 0
}

$findings |
    Sort-Object TimeCreated -Descending |
    Format-Table TimeCreated, Severity, RuleName, MITRE -AutoSize

$findings |
    Sort-Object TimeCreated -Descending |
    Export-Csv -Path $OutputPath -NoTypeInformation

$high = ($findings | Where-Object Severity -eq "High").Count
$medium = ($findings | Where-Object Severity -eq "Medium").Count

Write-Host ""
Write-Host "Summary"
Write-Host "-------"
Write-Host "High severity findings:   $high"
Write-Host "Medium severity findings: $medium"
Write-Host "Total findings:           $($findings.Count)"
Write-Host ""
Write-Host "Report exported to: $OutputPath"
