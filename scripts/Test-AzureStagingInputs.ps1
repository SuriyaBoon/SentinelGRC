[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ContainerImage,

    [Parameter(Mandatory = $true)]
    [string]$ValidationContainerImage,

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

function Assert-RegistryBoundImage {
    param(
        [Parameter(Mandatory = $true)] [string]$Image,
        [Parameter(Mandatory = $true)] [string]$ExpectedRegistryHost,
        [Parameter(Mandatory = $true)] [string]$ExpectedRepository,
        [Parameter(Mandatory = $true)] [string]$Label
    )
    if ($Image -notmatch '^(?<host>[a-z0-9]{5,50}\.azurecr\.io)/(?<repository>[a-z0-9._/-]+)@sha256:(?<digest>[a-f0-9]{64})$') {
        throw "$Label must be a lowercase ACR image pinned by a 64-character lowercase sha256 digest."
    }
    if ($Matches['host'] -cne $ExpectedRegistryHost) {
        throw "$Label registry must match the AcrPull registry $ExpectedRegistryHost."
    }
    if ($Matches['repository'] -cne $ExpectedRepository) {
        throw "$Label repository must be exactly $ExpectedRegistryHost/$ExpectedRepository."
    }
    [pscustomobject]@{
        repository = $Matches['repository']
        digest = $Matches['digest']
    }
}

if ($RegistryName -notmatch '^[a-zA-Z0-9]{5,50}$') {
    throw "RegistryName must be 5-50 alphanumeric characters."
}
$expectedRegistryHost = "$($RegistryName.ToLowerInvariant()).azurecr.io"
$runtimeImageResult = Assert-RegistryBoundImage -Image $ContainerImage -ExpectedRegistryHost $expectedRegistryHost -ExpectedRepository "sentinelgrc" -Label "ContainerImage"
$validationImageResult = Assert-RegistryBoundImage -Image $ValidationContainerImage -ExpectedRegistryHost $expectedRegistryHost -ExpectedRepository "sentinelgrc-assurance" -Label "ValidationContainerImage"

$subscriptionGuid = [Guid]::Empty
if (-not [Guid]::TryParse($RegistrySubscriptionId, [ref]$subscriptionGuid) -or
    $subscriptionGuid -eq [Guid]::Empty) {
    throw "RegistrySubscriptionId must be an Azure subscription GUID."
}

if ($RegistryResourceGroup -notmatch '^[a-zA-Z0-9._()-]{1,90}$' -or
    $RegistryResourceGroup.EndsWith(".")) {
    throw "RegistryResourceGroup is not a valid Azure resource-group name."
}

$audienceGuid = [Guid]::Empty
if (-not [Guid]::TryParse($OidcAudience, [ref]$audienceGuid) -or
    $audienceGuid -eq [Guid]::Empty) {
    throw "OidcAudience must be the non-empty application client ID GUID expected in an Entra v2 token aud claim."
}
$canonicalAudience = $audienceGuid.ToString()
if ($OidcAudience -cne $canonicalAudience) {
    throw "OidcAudience must be the canonical lowercase hyphenated GUID string."
}

$tenantGuid = [Guid]::Empty
if (-not [Guid]::TryParse($OidcTenantId, [ref]$tenantGuid) -or
    $tenantGuid -eq [Guid]::Empty) {
    throw "OidcTenantId must be a non-empty GUID."
}
$canonicalTenant = $tenantGuid.ToString()
if ($OidcTenantId -cne $canonicalTenant) {
    throw "OidcTenantId must be the canonical lowercase hyphenated GUID string."
}

$canonicalIssuer = "https://login.microsoftonline.com/$canonicalTenant/v2.0"
$canonicalJwksUrl = "https://login.microsoftonline.com/$canonicalTenant/discovery/v2.0/keys"
if ($OidcIssuer -cne $canonicalIssuer) {
    throw "OidcIssuer must exactly match the tenant-derived canonical Microsoft Entra v2 issuer."
}
if ($OidcJwksUrl -cne $canonicalJwksUrl) {
    throw "OidcJwksUrl must exactly match the tenant-derived canonical Microsoft Entra v2 JWKS URL."
}

if ($runtimeImageResult.digest -ceq $validationImageResult.digest) {
    throw "ContainerImage and ValidationContainerImage must use different sha256 digests."
}

[pscustomobject]@{
    status = "valid"
    image_is_digest_pinned = $true
    validation_image_is_digest_pinned = $true
    image_registry_bound = $true
    validation_image_registry_bound = $true
    runtime_repository_bound = $true
    validation_repository_bound = $true
    image_separation_enforced = $true
    tenant_bound_endpoints = $true
    registry = $expectedRegistryHost
    oidc_issuer = $canonicalIssuer
    oidc_audience = $canonicalAudience
    oidc_tenant_id = $canonicalTenant
    oidc_jwks_url = $canonicalJwksUrl
    azure_mutation_performed = $false
} | ConvertTo-Json
