[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ContainerImage,

    [Parameter(Mandatory = $true)]
    [string]$RegistrySubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$RegistryResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$RegistryName,

    [Parameter(Mandatory = $true)]
    [string]$OidcIssuer,

    [Parameter(Mandatory = $true)]
    [string]$OidcAudience,

    [Parameter(Mandatory = $true)]
    [string]$OidcTenantId,

    [Parameter(Mandatory = $true)]
    [string]$OidcJwksUrl
)

$ErrorActionPreference = "Stop"

if ($ContainerImage -notmatch '^[a-z0-9][a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$') {
    throw "ContainerImage must be a registry image pinned by a 64-character sha256 digest."
}

$subscriptionGuid = [Guid]::Empty
if (-not [Guid]::TryParse($RegistrySubscriptionId, [ref]$subscriptionGuid) -or
    $subscriptionGuid -eq [Guid]::Empty) {
    throw "RegistrySubscriptionId must be an Azure subscription GUID."
}

if ($RegistryResourceGroup -notmatch '^[a-zA-Z0-9._()-]{1,90}$' -or
    $RegistryResourceGroup.EndsWith(".")) {
    throw "RegistryResourceGroup is not a valid Azure resource-group name."
}

if ($RegistryName -notmatch '^[a-zA-Z0-9]{5,50}$') {
    throw "RegistryName must be 5-50 alphanumeric characters."
}

$issuer = $null
if (-not [Uri]::TryCreate($OidcIssuer, [UriKind]::Absolute, [ref]$issuer) -or
    $issuer.Scheme -ne "https") {
    throw "OidcIssuer must be an absolute HTTPS URL."
}

if ([string]::IsNullOrWhiteSpace($OidcAudience)) {
    throw "OidcAudience is required."
}

$tenantGuid = [Guid]::Empty
if (-not [Guid]::TryParse($OidcTenantId, [ref]$tenantGuid) -or
    $tenantGuid -eq [Guid]::Empty) {
    throw "OidcTenantId must be a non-empty GUID."
}

$jwks = $null
if (-not [Uri]::TryCreate($OidcJwksUrl, [UriKind]::Absolute, [ref]$jwks) -or
    $jwks.Scheme -ne "https") {
    throw "OidcJwksUrl must be an absolute HTTPS URL."
}

[pscustomobject]@{
    status = "valid"
    image_is_digest_pinned = $true
    registry = "$RegistryName.azurecr.io"
    oidc_issuer = $issuer.AbsoluteUri
    oidc_audience = $OidcAudience
    oidc_tenant_id = $tenantGuid.ToString()
    oidc_jwks_url = $jwks.AbsoluteUri
    azure_mutation_performed = $false
} | ConvertTo-Json
