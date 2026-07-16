#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\ad-access-review.json",
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$reviewedAt = (Get-Date).ToUniversalTime().ToString("o")
$staleBefore = (Get-Date).AddDays(-$StaleDays)
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
$privilegedMembers = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($groupName in $privilegedGroups) {
    try {
        Get-ADGroupMember -Identity $groupName -Recursive |
            Where-Object { $_.objectClass -eq "user" } |
            ForEach-Object { [void]$privilegedMembers.Add($_.SamAccountName) }
    } catch {
        Write-Error "Could not review group '$groupName': $($_.Exception.Message)"
        exit 1
    }
}

$users = Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,Department |
    ForEach-Object {
        $lastLogon = $_.LastLogonDate
        [ordered]@{
            sam_account_name = $_.SamAccountName
            enabled = [bool]$_.Enabled
            department = $_.Department
            last_logon = if ($null -eq $lastLogon) { $null } else { ([datetime]$lastLogon).ToUniversalTime().ToString("o") }
            password_last_set = if ($null -eq $_.PasswordLastSet) { $null } else { ([datetime]$_.PasswordLastSet).ToUniversalTime().ToString("o") }
            privileged = $privilegedMembers.Contains($_.SamAccountName)
            stale = ($null -eq $lastLogon -or [datetime]$lastLogon -lt $staleBefore)
        }
    }

$review = [ordered]@{
    schema_version = "1.0"
    reviewed_at = $reviewedAt
    stale_days = $StaleDays
    privileged_groups = $privilegedGroups
    users = @($users)
    mutation_performed = $false
}

$parent = Split-Path -Parent (Resolve-Path -LiteralPath $OutputPath -ErrorAction SilentlyContinue)
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    throw "Output directory does not exist: $parent"
}
$review | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "AD access review exported to $OutputPath"
