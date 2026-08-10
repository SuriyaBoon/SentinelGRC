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
        [Parameter(Mandatory = $true)] [string]$Label
    )
    if ($Image -notmatch '^(?<host>[a-z0-9]{5,50}\.azurecr\.io)/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$') {
        throw "$Label must be a lowercase ACR image pinned by a 64-character sha256 digest."
    }
    if ($Matches['host'] -ine $ExpectedRegistryHost) {
        throw "$Label registry must match the AcrPull registry $ExpectedRegistryHost."
    }
}

if ($RegistryName -notmatch '^[a-zA-Z0-9]{5,50}$') {
    throw "RegistryName must be 5-50 alphanumeric characters."
}
$expectedRegistryHost = "$($RegistryName.ToLowerInvariant()).azurecr.io"
Assert-RegistryBoundImage -Image $ContainerImage -ExpectedRegistryHost $expectedRegistryHost -Label "ContainerImage"
Assert-RegistryBoundImage -Image $ValidationContainerImage -ExpectedRegistryHost $expectedRegistryHost -Label "ValidationContainerImage"

$subscriptionGuid = [Guid]::Empty
if (-not [Guid]::TryParse($RegistrySubscriptionId, [ref]$subscriptionGuid) -or
    $subscriptionGuid -eq [Guid]::Empty) {
    throw "RegistrySubscriptionId must be an Azure subscription GUID."
}

if ($RegistryResourceGroup -notmatch '^[a-zA-Z0-9._()-]{1,90}$' -or
    $RegistryResourceGroup.EndsWith(".")) {
    throw "RegistryResourceGroup is not a valid Azure resource-group name."
}

$issuer = $null
if (-not [Uri]::TryCreate($OidcIssuer, [UriKind]::Absolute, [ref]$issuer) -or
    $issuer.Scheme -ne "https") {
    throw "OidcIssuer must be an absolute HTTPS URL."
}

$audienceGuid = [Guid]::Empty
if (-not [Guid]::TryParse($OidcAudience, [ref]$audienceGuid) -or
    $audienceGuid -eq [Guid]::Empty) {
    throw "OidcAudience must be the non-empty application client ID GUID expected in an Entra v2 token aud claim."
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
    validation_image_is_digest_pinned = $true
    image_registry_bound = $true
    validation_image_registry_bound = $true
    registry = $expectedRegistryHost
    oidc_issuer = $issuer.AbsoluteUri
    oidc_audience = $audienceGuid.ToString()
    oidc_tenant_id = $tenantGuid.ToString()
    oidc_jwks_url = $jwks.AbsoluteUri
    azure_mutation_performed = $false
} | ConvertTo-Json
