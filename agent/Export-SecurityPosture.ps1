#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\posture.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-CheckResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $false)]$Value = $null,
        [Parameter(Mandatory = $false)][string]$Error = $null
    )

    [ordered]@{
        name   = $Name
        passed = $Passed
        value  = $Value
        error  = $Error
    }
}

function Invoke-ReadOnlyCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Check
    )

    try {
        & $Check
    }
    catch {
        New-CheckResult -Name $Name -Passed $false -Error $_.Exception.Message
    }
}

function Get-SystemUpdateAgeDays {
    $latest = Get-HotFix |
        Where-Object { $_.InstalledOn -ne $null } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1

    if ($null -eq $latest) {
        throw "No installed update date was available."
    }

    [math]::Floor(((Get-Date) - [datetime]$latest.InstalledOn).TotalDays)
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$firewall = Get-NetFirewallProfile
$defender = Get-MpComputerStatus
$bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive
$updateAge = Get-SystemUpdateAgeDays

$checks = @(
    (Invoke-ReadOnlyCheck -Name "bitlocker_system_drive" -Check {
        $protected = $bitlocker.ProtectionStatus -eq "On"
        New-CheckResult -Name "bitlocker_system_drive" -Passed $protected -Value $protected
    }),
    (Invoke-ReadOnlyCheck -Name "firewall_all_profiles_enabled" -Check {
        $enabled = @($firewall | Where-Object { $_.Enabled -ne $true }).Count -eq 0
        New-CheckResult -Name "firewall_all_profiles_enabled" -Passed $enabled -Value $enabled
    }),
    (Invoke-ReadOnlyCheck -Name "defender_realtime_enabled" -Check {
        $enabled = $defender.RealTimeProtectionEnabled -eq $true
        New-CheckResult -Name "defender_realtime_enabled" -Passed $enabled -Value $enabled
    }),
    (Invoke-ReadOnlyCheck -Name "days_since_last_update" -Check {
        New-CheckResult -Name "days_since_last_update" -Passed ($updateAge -le 30) -Value $updateAge
    })
)

$posture = [ordered]@{
    schema_version = "1.0"
    collected_at   = (Get-Date).ToUniversalTime().ToString("o")
    asset_id       = $env:COMPUTERNAME
    hostname       = $env:COMPUTERNAME
    os             = $os.Caption
    os_version     = $os.Version
    domain         = $computer.PartOfDomain
    checks         = $checks
    # Only the control fields consumed by controls.json are exported.
    bitlocker_system_drive       = [bool]$checks[0].value
    firewall_all_profiles_enabled = [bool]$checks[1].value
    defender_realtime_enabled    = [bool]$checks[2].value
    days_since_last_update       = $checks[3].value
}

$parent = Split-Path -Parent (Resolve-Path -LiteralPath $OutputPath -ErrorAction SilentlyContinue)
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    throw "Output directory does not exist: $parent"
}

$posture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "Posture exported to $OutputPath"
