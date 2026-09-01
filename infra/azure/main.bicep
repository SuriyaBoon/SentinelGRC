targetScope = 'resourceGroup'

@description('Short lowercase prefix used in Azure resource names.')
@minLength(3)
@maxLength(10)
param namePrefix string

@allowed([
  'staging'
])
@description('This template is intentionally limited to the staging environment.')
param environmentName string = 'staging'

@description('Azure region for the staging resources.')
param location string = resourceGroup().location

@description('Globally unique PostgreSQL server name.')
@minLength(3)
@maxLength(63)
param databaseServerName string = toLower(replace(
  '${namePrefix}${environmentName}${uniqueString(resourceGroup().id)}pg',
  '-',
  ''
))

@description('Immutable SentinelGRC image reference. A digest, not a mutable tag, is required.')
@minLength(80)
param containerImage string

@description('Immutable staging-validation image reference. A separate digest is required so validation utilities do not ship in the runtime image.')
@minLength(80)
param validationContainerImage string

@description('Deploy the Container App only after the digest-pinned image exists in ACR.')
param deployApplication bool = false

@description('Deploy role-isolated manual staging validation jobs after the private application exists.')
param deployValidationJobs bool = false

@description('Deploy the isolated restored-PostgreSQL validation job only after a private point-in-time restore exists.')
param deployRestoreValidationJob bool = false

@secure()
@description('Private restored PostgreSQL URL used only by the opt-in restore validation job.')
param restoredDatabaseUrl string = ''

@description('Existing isolated PostgreSQL Flexible Server created by the approved point-in-time restore.')
param restoredDatabaseServerName string = ''

@secure()
@description('Per-run HMAC key used only to pseudonymize database target identity in validation evidence.')
param validationEvidenceHmacKey string = ''

@description('Deploy staging availability and outbox-health alert rules.')
param deployMonitoringAlerts bool = false

@description('Optional existing Azure Monitor Action Group resource ID. Empty keeps alerts observable without notifications.')
param monitoringActionGroupResourceId string = ''

@description('Subscription containing the existing Azure Container Registry.')
param containerRegistrySubscriptionId string

@description('Resource group containing the existing Azure Container Registry.')
param containerRegistryResourceGroup string

@description('Name of the existing Azure Container Registry.')
param containerRegistryName string

@description('PostgreSQL administrator login used only to bootstrap the staging database.')
@minLength(1)
param databaseAdministratorLogin string

@secure()
@description('PostgreSQL bootstrap password. Supply it at deployment time; never commit it.')
@minLength(16)
param databaseAdministratorPassword string

@description('Microsoft Entra issuer that the runtime verifies exactly.')
@minLength(8)
param oidcIssuer string

@description('Application client ID GUID expected in the aud claim of Microsoft Entra v2 access tokens. This is not the api:// token-request scope.')
@minLength(36)
@maxLength(36)
param oidcAudience string

@description('Microsoft Entra tenant GUID that the runtime verifies in the tid claim.')
@minLength(36)
@maxLength(36)
param oidcTenantId string

@description('HTTPS JWKS endpoint used to verify Microsoft Entra token signatures.')
@minLength(8)
param oidcJwksUrl string

@minValue(7)
@maxValue(35)
@description('Online backup retention for PostgreSQL Flexible Server.')
param databaseBackupRetentionDays int = 14

@minValue(7)
@maxValue(365)
@description('Soft-delete retention for evidence and audit blobs.')
param blobDeleteRetentionDays int = 30

@minValue(7)
@maxValue(365)
@description('Unlocked staging audit-retention policy. Lock only after an approved live validation.')
param auditImmutabilityDays int = 30

@description('Common resource tags.')
param tags object = {
  application: 'SentinelGRC'
  environment: environmentName
  managedBy: 'Bicep'
  dataClassification: 'security-governance'
}

var suffix = uniqueString(resourceGroup().id)
var baseName = toLower('${namePrefix}-${environmentName}-${suffix}')
var compactName = toLower(replace('${namePrefix}${environmentName}${suffix}', '-', ''))
var vnetName = '${baseName}-vnet'
var containerSubnetName = 'container-apps'
var databaseSubnetName = 'postgresql'
var privateEndpointSubnetName = 'private-endpoints'
var identityName = '${baseName}-app-id'
var runtimeImagePullIdentityName = '${baseName}-runtime-pull-id'
var publisherIdentityName = '${baseName}-publisher-id'
var validationImagePullIdentityName = '${baseName}-validation-pull-id'
var validationAnalystIdentityName = '${baseName}-validation-analyst-id'
var validationApproverIdentityName = '${baseName}-validation-approver-id'
var validationServiceBusReceiverIdentityName = '${baseName}-validation-bus-receiver-id'
var validationSourceDatabaseIdentityName = '${baseName}-validation-source-db-id'
var validationRestoredDatabaseIdentityName = '${baseName}-validation-restored-db-id'
var validationAnalystJobName = '${baseName}-analyst-validation'
var validationApproverJobName = '${baseName}-approver-validation'
var validationServiceBusJobName = '${baseName}-bus-validation'
var validationSourceDatabaseJobName = '${baseName}-source-db-validation'
var validationRestoredDatabaseJobName = '${baseName}-restored-db-validation'
var monitoringQueryIdentityName = '${baseName}-monitor-query-id'
var availabilityAlertName = '${baseName}-no-replicas'
var outboxHealthAlertName = '${baseName}-outbox-health'
var workspaceName = '${baseName}-logs'
var appInsightsName = '${baseName}-appi'
var environmentResourceName = '${baseName}-cae'
var appName = '${baseName}-api'
var publisherAppName = '${baseName}-publisher'
var databaseName = 'sentinelgrc'
var storageAccountName = take('${compactName}data', 24)
var keyVaultName = take('${baseName}-kv', 24)
var serviceBusName = take('${baseName}-bus', 50)
var serviceBusQueueName = 'governance-outbox'
var evidenceContainerName = 'evidence'
var auditContainerName = 'audit-archive'
var databaseSecretName = 'sentinel-database-url'
var hexCharacters = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
var emptyGuid = '00000000-0000-0000-0000-000000000000'
var expectedRegistryHost = toLower('${containerRegistryName}.azurecr.io')
var expectedRuntimeImageRepository = '${expectedRegistryHost}/sentinelgrc'
var expectedValidationImageRepository = '${expectedRegistryHost}/sentinelgrc-assurance'
var containerImageParts = split(containerImage, '@sha256:')
var containerImageRepository = length(containerImageParts) == 2 ? containerImageParts[0] : ''
var containerImageRepositoryParts = split(containerImageRepository, '/')
var containerImageHost = length(containerImageRepositoryParts) > 1 ? toLower(first(containerImageRepositoryParts)) : ''
var containerImageDigest = length(containerImageParts) == 2 ? containerImageParts[1] : ''
var containerImageInvalidDigestCharacters = reduce(
  hexCharacters,
  containerImageDigest,
  (remaining, character) => replace(remaining, character, '')
)
var imageDigestPinned = length(containerImageParts) == 2 && containerImageRepository == expectedRuntimeImageRepository && containerImageHost == expectedRegistryHost && length(containerImageDigest) == 64 && empty(containerImageInvalidDigestCharacters)
var validationImageParts = split(validationContainerImage, '@sha256:')
var validationImageRepository = length(validationImageParts) == 2 ? validationImageParts[0] : ''
var validationImageRepositoryParts = split(validationImageRepository, '/')
var validationImageHost = length(validationImageRepositoryParts) > 1 ? toLower(first(validationImageRepositoryParts)) : ''
var validationImageDigest = length(validationImageParts) == 2 ? validationImageParts[1] : ''
var validationImageInvalidDigestCharacters = reduce(
  hexCharacters,
  validationImageDigest,
  (remaining, character) => replace(remaining, character, '')
)
var validationImageDigestPinned = length(validationImageParts) == 2 && validationImageRepository == expectedValidationImageRepository && validationImageHost == expectedRegistryHost && length(validationImageDigest) == 64 && empty(validationImageInvalidDigestCharacters)
var oidcTenantIdWithoutHyphens = replace(oidcTenantId, '-', '')
var oidcTenantIdInvalidCharacters = reduce(
  hexCharacters,
  oidcTenantIdWithoutHyphens,
  (remaining, character) => replace(remaining, character, '')
)
var oidcTenantIdCanonical = oidcTenantId != emptyGuid && oidcTenantId == toLower(oidcTenantId) && length(oidcTenantIdWithoutHyphens) == 32 && empty(oidcTenantIdInvalidCharacters) && substring(oidcTenantId, 8, 1) == '-' && substring(oidcTenantId, 13, 1) == '-' && substring(oidcTenantId, 18, 1) == '-' && substring(oidcTenantId, 23, 1) == '-'
var oidcAudienceWithoutHyphens = replace(oidcAudience, '-', '')
var oidcAudienceInvalidCharacters = reduce(
  hexCharacters,
  oidcAudienceWithoutHyphens,
  (remaining, character) => replace(remaining, character, '')
)
var oidcAudienceCanonical = oidcAudience != emptyGuid && oidcAudience == toLower(oidcAudience) && length(oidcAudienceWithoutHyphens) == 32 && empty(oidcAudienceInvalidCharacters) && substring(oidcAudience, 8, 1) == '-' && substring(oidcAudience, 13, 1) == '-' && substring(oidcAudience, 18, 1) == '-' && substring(oidcAudience, 23, 1) == '-'
var canonicalOidcIssuer = 'https://login.microsoftonline.com/${oidcTenantId}/v2.0'
var canonicalOidcJwksUrl = 'https://login.microsoftonline.com/${oidcTenantId}/discovery/v2.0/keys'
var oidcTrustInputsCanonical = oidcTenantIdCanonical && oidcAudienceCanonical && oidcIssuer == canonicalOidcIssuer && oidcJwksUrl == canonicalOidcJwksUrl
var deployValidatedApplication = validationImageDigest == containerImageDigest
  ? fail('containerImage and validationContainerImage must use separate sha256 digests')
  : !oidcTrustInputsCanonical
    ? fail('oidcTenantId, oidcAudience, oidcIssuer, and oidcJwksUrl must be canonical non-empty tenant-bound Entra inputs')
    : !deployApplication
      ? false
      : imageDigestPinned
        ? true
        : fail('deployApplication requires a lowercase digest-pinned runtime image from containerRegistryName.azurecr.io/sentinelgrc')
var deployValidatedJobs = !deployValidationJobs
  ? false
  : !deployValidatedApplication
    ? fail('deployValidationJobs requires deployApplication=true with valid canonical OIDC inputs and a valid runtime image')
    : !validationImageDigestPinned
      ? fail('deployValidationJobs requires a lowercase digest-pinned validation image from containerRegistryName.azurecr.io/sentinelgrc-assurance')
      : length(validationEvidenceHmacKey) < 32 || length(validationEvidenceHmacKey) > 256
        ? fail('deployValidationJobs requires a 32-256 character evidence HMAC key supplied as a secure parameter')
        : true
var restoredDatabaseServerNameCanonical = length(restoredDatabaseServerName) >= 3 && length(restoredDatabaseServerName) <= 63 && restoredDatabaseServerName == toLower(restoredDatabaseServerName) && !startsWith(restoredDatabaseServerName, '-') && !endsWith(restoredDatabaseServerName, '-')
var deployValidatedRestoreJob = !deployRestoreValidationJob
  ? false
  : !deployValidatedJobs
    ? fail('deployRestoreValidationJob requires deployValidationJobs=true with valid application and validation images')
    : !restoredDatabaseServerNameCanonical || restoredDatabaseServerName == databaseServerName
      ? fail('deployRestoreValidationJob requires a distinct existing restoredDatabaseServerName')
      : !startsWith(restoredDatabaseUrl, 'postgresql://') && !startsWith(restoredDatabaseUrl, 'postgresql+psycopg://')
      ? fail('deployRestoreValidationJob requires a secure PostgreSQL restoredDatabaseUrl')
      : true
var deployValidatedMonitoring = !deployMonitoringAlerts
  ? false
  : deployValidatedApplication
    ? true
    : fail('deployMonitoringAlerts requires deployApplication=true with valid canonical OIDC inputs and a valid runtime image')

var roleDefinitionResourceType = 'Microsoft.Authorization/roleDefinitions'
var keyVaultSecretsUserRoleId = subscriptionResourceId(
  roleDefinitionResourceType,
  '4633458b-17de-408a-b874-0445c86b69e6'
)
var storageBlobContributorRoleId = subscriptionResourceId(
  roleDefinitionResourceType,
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var serviceBusSenderRoleId = subscriptionResourceId(
  roleDefinitionResourceType,
  '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
)
var serviceBusReceiverRoleId = subscriptionResourceId(
  roleDefinitionResourceType,
  '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'
)
var logAnalyticsReaderRoleId = subscriptionResourceId(
  roleDefinitionResourceType,
  '73c42c96-874c-492b-b04d-ab87d138a893'
)

resource containerSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: containerSubnetName
}

resource databaseSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: databaseSubnetName
}

resource privateEndpointSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: privateEndpointSubnetName
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
  name: containerRegistryName
}

resource restoredPostgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' existing = if (deployValidatedRestoreJob) {
  name: restoredDatabaseServerName
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.40.0.0/20'
      ]
    }
    subnets: [
      {
        name: containerSubnetName
        properties: {
          addressPrefix: '10.40.0.0/23'
          delegations: [
            {
              name: 'Microsoft.App.environments'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: databaseSubnetName
        properties: {
          addressPrefix: '10.40.2.0/24'
          delegations: [
            {
              name: 'Microsoft.DBforPostgreSQL.flexibleServers'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: privateEndpointSubnetName
        properties: {
          addressPrefix: '10.40.3.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource postgresPrivateDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource blobPrivateDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
  tags: tags
}

resource vaultPrivateDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: tags
}

resource serviceBusPrivateDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
  tags: tags
}

resource acrPrivateDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.azurecr.io'
  location: 'global'
  tags: tags
}

resource postgresDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: postgresPrivateDns
  name: '${baseName}-pg-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource blobDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: blobPrivateDns
  name: '${baseName}-blob-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource vaultDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: vaultPrivateDns
  name: '${baseName}-vault-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource serviceBusDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: serviceBusPrivateDns
  name: '${baseName}-bus-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource acrDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: acrPrivateDns
  name: '${baseName}-acr-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource appIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: tags
}

resource validationImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedJobs) {
  name: validationImagePullIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-validation-image-pull'
  })
}

resource validationAnalystIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedJobs) {
  name: validationAnalystIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'analyst'
  })
}

resource validationApproverIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedJobs) {
  name: validationApproverIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'approver'
  })
}

resource runtimeImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: runtimeImagePullIdentityName
  location: location
  tags: union(tags, {
    purpose: 'runtime-image-pull'
  })
}

resource publisherIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: publisherIdentityName
  location: location
  tags: union(tags, {
    purpose: 'service-bus-publisher'
  })
}

resource validationServiceBusReceiverIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedJobs) {
  name: validationServiceBusReceiverIdentityName
  location: location
  tags: union(tags, {
    purpose: 'service-bus-receiver-validation'
  })
}

resource validationSourceDatabaseIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedJobs) {
  name: validationSourceDatabaseIdentityName
  location: location
  tags: union(tags, {
    purpose: 'source-postgresql-validation'
  })
}

resource validationRestoredDatabaseIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedRestoreJob) {
  name: validationRestoredDatabaseIdentityName
  location: location
  tags: union(tags, {
    purpose: 'restored-postgresql-validation'
  })
}

resource monitoringQueryIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployValidatedMonitoring) {
  name: monitoringQueryIdentityName
  location: location
  tags: union(tags, {
    purpose: 'outbox-health-query'
  })
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    features: {
      disableLocalAuth: true
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    retentionInDays: 30
    sku: {
      name: 'PerGB2018'
    }
    workspaceCapping: {
      dailyQuotaGb: 1
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    DisableLocalAuth: true
    IngestionMode: 'LogAnalytics'
    WorkspaceResourceId: logAnalytics.id
  }
}

resource containerEnvironment 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: environmentResourceName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
    vnetConfiguration: {
      infrastructureSubnetId: containerSubnet.id
      internal: true
    }
  }
}

resource containerEnvironmentDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (deployValidatedMonitoring) {
  scope: containerEnvironment
  name: 'sentinelgrc-staging-logs'
  properties: {
    logs: [
      {
        category: 'ContainerAppConsoleLogs'
        enabled: true
      }
      {
        category: 'ContainerAppSystemLogs'
        enabled: true
      }
    ]
    workspaceId: logAnalytics.id
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: databaseServerName
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  identity: {
    type: 'SystemAssigned'
  }
  dependsOn: [
    postgresDnsLink
  ]
  tags: tags
  properties: {
    administratorLogin: databaseAdministratorLogin
    administratorLoginPassword: databaseAdministratorPassword
    authConfig: {
      activeDirectoryAuth: 'Disabled'
      passwordAuth: 'Enabled'
    }
    availabilityZone: '1'
    backup: {
      backupRetentionDays: databaseBackupRetentionDays
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: databaseSubnet.id
      privateDnsZoneArmResourceId: postgresPrivateDns.id
      publicNetworkAccess: 'Disabled'
    }
    storage: {
      autoGrow: 'Enabled'
      storageSizeGB: 32
    }
    version: '17'
  }
}

resource governanceDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: postgres
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_ZRS'
  }
  kind: 'StorageV2'
  identity: {
    type: 'SystemAssigned'
  }
  tags: tags
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
        file: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    containerDeleteRetentionPolicy: {
      days: blobDeleteRetentionDays
      enabled: true
    }
    deleteRetentionPolicy: {
      allowPermanentDelete: false
      days: blobDeleteRetentionDays
      enabled: true
    }
    isVersioningEnabled: true
  }
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: evidenceContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: auditContainerName
  properties: {
    immutableStorageWithVersioning: {
      enabled: true
    }
    publicAccess: 'None'
  }
}

resource auditImmutabilityPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: auditContainer
  name: 'default'
  properties: {
    allowProtectedAppendWrites: true
    immutabilityPeriodSinceCreationInDays: auditImmutabilityDays
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    accessPolicies: []
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    publicNetworkAccess: 'Disabled'
    sku: {
      family: 'A'
      name: 'standard'
    }
    softDeleteRetentionInDays: 90
    tenantId: subscription().tenantId
  }
}

resource databaseUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: databaseSecretName
  dependsOn: [
    governanceDatabase
  ]
  properties: {
    value: 'postgresql://${databaseAdministratorLogin}:${uriComponent(databaseAdministratorPassword)}@${postgres.properties.fullyQualifiedDomainName}:5432/${databaseName}?sslmode=require'
  }
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: serviceBusName
  location: location
  sku: {
    capacity: 1
    name: 'Premium'
    tier: 'Premium'
  }
  identity: {
    type: 'SystemAssigned'
  }
  tags: tags
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    premiumMessagingPartitions: 1
    publicNetworkAccess: 'Disabled'
    zoneRedundant: false
  }
}

resource governanceQueue 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: serviceBus
  name: serviceBusQueueName
  properties: {
    deadLetteringOnMessageExpiration: true
    defaultMessageTimeToLive: 'P14D'
    duplicateDetectionHistoryTimeWindow: 'PT10M'
    enableBatchedOperations: true
    enableExpress: false
    // Premium namespace partitioning is configured at namespace creation. Azure
    // normalizes the child queue flag to false; matching that effective value
    // keeps repeated ARM deployments idempotent because this flag is immutable.
    enablePartitioning: false
    lockDuration: 'PT1M'
    maxDeliveryCount: 10
    maxSizeInMegabytes: 1024
    requiresDuplicateDetection: true
    requiresSession: true
    status: 'Active'
  }
}

resource blobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${baseName}-blob-pe'
  location: location
  tags: tags
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          groupIds: [
            'blob'
          ]
          privateLinkServiceId: storage.id
        }
      }
    ]
    subnet: {
      id: privateEndpointSubnet.id
    }
  }
}

resource blobPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: blobPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobPrivateDns.id
        }
      }
    ]
  }
}

resource vaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${baseName}-vault-pe'
  location: location
  tags: tags
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          groupIds: [
            'vault'
          ]
          privateLinkServiceId: keyVault.id
        }
      }
    ]
    subnet: {
      id: privateEndpointSubnet.id
    }
  }
}

resource vaultPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: vaultPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: vaultPrivateDns.id
        }
      }
    ]
  }
}

resource serviceBusPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${baseName}-bus-pe'
  location: location
  tags: tags
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'namespace'
        properties: {
          groupIds: [
            'namespace'
          ]
          privateLinkServiceId: serviceBus.id
        }
      }
    ]
    subnet: {
      id: privateEndpointSubnet.id
    }
  }
}

resource serviceBusPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: serviceBusPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'servicebus'
        properties: {
          privateDnsZoneId: serviceBusPrivateDns.id
        }
      }
    ]
  }
}

resource acrPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${baseName}-acr-pe'
  location: location
  tags: tags
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'registry'
        properties: {
          groupIds: [
            'registry'
          ]
          privateLinkServiceId: registry.id
        }
      }
    ]
    subnet: {
      id: privateEndpointSubnet.id
    }
  }
}

resource acrPrivateDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: acrPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'registry'
        properties: {
          privateDnsZoneId: acrPrivateDns.id
        }
      }
    ]
  }
}

resource keyVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, appIdentity.id, keyVaultSecretsUserRoleId)
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

resource evidenceBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceContainer
  name: guid(evidenceContainer.id, appIdentity.id, storageBlobContributorRoleId)
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobContributorRoleId
  }
}

resource auditBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: auditContainer
  name: guid(auditContainer.id, appIdentity.id, storageBlobContributorRoleId)
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobContributorRoleId
  }
}

resource serviceBusSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: governanceQueue
  name: guid(governanceQueue.id, publisherIdentity.id, serviceBusSenderRoleId)
  properties: {
    principalId: publisherIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusSenderRoleId
  }
}

resource publisherDatabaseSecretReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: databaseUrlSecret
  name: guid(databaseUrlSecret.id, publisherIdentity.id, keyVaultSecretsUserRoleId)
  properties: {
    principalId: publisherIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

resource validationServiceBusReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployValidatedJobs) {
  scope: governanceQueue
  name: guid(governanceQueue.id, validationServiceBusReceiverIdentity!.id, serviceBusReceiverRoleId)
  properties: {
    principalId: validationServiceBusReceiverIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusReceiverRoleId
  }
}

resource validationSourceDatabaseSecretReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployValidatedJobs) {
  scope: databaseUrlSecret
  name: guid(databaseUrlSecret.id, validationSourceDatabaseIdentity!.id, keyVaultSecretsUserRoleId)
  properties: {
    principalId: validationSourceDatabaseIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

resource containerApp 'Microsoft.App/containerApps@2025-01-01' = if (deployValidatedApplication) {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${appIdentity.id}': {}
      '${runtimeImagePullIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    acrPull
    auditBlobContributor
    blobPrivateDnsGroup
    keyVaultSecretsUser
    vaultPrivateDnsGroup
  ]
  tags: tags
  properties: {
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        // mTLS is intentionally not asserted without certificate issuance,
        // rotation, revocation, and application-side XFCC validation. This
        // internal ingress uses Entra OIDC and role-isolated managed identities.
        // See docs/sonar-security-remediation.md for the reviewed boundary.
        allowInsecure: false
        external: false
        targetPort: 8080
        transport: 'auto'
      }
      registries: [
        {
          identity: runtimeImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      secrets: [
        {
          identity: appIdentity.id
          keyVaultUrl: databaseUrlSecret.properties.secretUriWithVersion
          name: 'database-url'
        }
      ]
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          env: [
            {
              name: 'SENTINEL_ENV'
              value: 'staging'
            }
            {
              name: 'SENTINEL_DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'SENTINEL_IDENTITY_DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'SENTINEL_EVIDENCE_DIR'
              value: '/tmp/sentinel-evidence'
            }
            {
              name: 'SENTINEL_AUDIT_DIR'
              value: '/tmp/sentinel-audit'
            }
            {
              name: 'SENTINEL_OUTBOX_DIR'
              value: '/tmp/sentinel-outbox'
            }
            {
              name: 'SENTINEL_EVIDENCE_STORE_URL'
              value: '${storage.properties.primaryEndpoints.blob}${evidenceContainerName}'
            }
            {
              name: 'SENTINEL_AZURE_CLIENT_ID'
              value: appIdentity.properties.clientId
            }
            {
              name: 'SENTINEL_AUDIT_ARCHIVE_URL'
              value: '${storage.properties.primaryEndpoints.blob}${auditContainerName}'
            }
            {
              name: 'SENTINEL_OIDC_ISSUER'
              value: oidcIssuer
            }
            {
              name: 'SENTINEL_OIDC_AUDIENCE'
              value: oidcAudience
            }
            {
              name: 'SENTINEL_OIDC_TENANT_ID'
              value: oidcTenantId
            }
            {
              name: 'SENTINEL_OIDC_JWKS_URL'
              value: oidcJwksUrl
            }
            {
              name: 'SENTINEL_REQUIRE_TLS'
              value: 'true'
            }
            {
              name: 'SENTINEL_SERVICE_BUS_NAMESPACE'
              value: '${serviceBus.name}.servicebus.windows.net'
            }
            {
              name: 'SENTINEL_SERVICE_BUS_QUEUE'
              value: governanceQueue.name
            }
          ]
          image: containerImage
          name: 'sentinelgrc'
          probes: [
            {
              httpGet: {
                path: '/healthz'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 10
              periodSeconds: 30
              type: 'Liveness'
            }
            {
              httpGet: {
                path: '/ready'
                port: 8080
                scheme: 'HTTP'
              }
              initialDelaySeconds: 10
              periodSeconds: 15
              type: 'Readiness'
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        maxReplicas: 2
        minReplicas: 1
        rules: [
          {
            custom: {
              metadata: {
                concurrentRequests: '20'
              }
              type: 'http'
            }
            name: 'http-concurrency'
          }
        ]
      }
    }
    workloadProfileName: 'Consumption'
  }
}

resource outboxPublisherApp 'Microsoft.App/containerApps@2025-01-01' = if (deployValidatedApplication) {
  name: publisherAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${publisherIdentity.id}': {}
      '${runtimeImagePullIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    acrPull
    publisherDatabaseSecretReader
    serviceBusPrivateDnsGroup
    serviceBusSender
    vaultPrivateDnsGroup
  ]
  tags: union(tags, {
    purpose: 'service-bus-publisher'
  })
  properties: {
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [
        {
          identity: runtimeImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      secrets: [
        {
          identity: publisherIdentity.id
          keyVaultUrl: databaseUrlSecret.properties.secretUriWithVersion
          name: 'database-url'
        }
      ]
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            'outbox_worker.py'
            '--run-forever'
            '--poll-seconds'
            '2'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_ENV'
              value: 'staging'
            }
            {
              name: 'SENTINEL_DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'SENTINEL_OUTBOX_DIR'
              value: '/tmp/sentinel-outbox'
            }
            {
              name: 'SENTINEL_AZURE_CLIENT_ID'
              value: publisherIdentity.properties.clientId
            }
            {
              name: 'SENTINEL_SERVICE_BUS_NAMESPACE'
              value: '${serviceBus.name}.servicebus.windows.net'
            }
            {
              name: 'SENTINEL_SERVICE_BUS_QUEUE'
              value: governanceQueue.name
            }
          ]
          image: containerImage
          name: 'outbox-publisher'
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
      scale: {
        maxReplicas: 1
        minReplicas: 1
      }
    }
    workloadProfileName: 'Consumption'
  }
}

resource monitoringQueryReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployValidatedMonitoring) {
  scope: logAnalytics
  name: guid(logAnalytics.id, monitoringQueryIdentity!.id, logAnalyticsReaderRoleId)
  properties: {
    principalId: monitoringQueryIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: logAnalyticsReaderRoleId
  }
}

resource validationAnalystJob 'Microsoft.App/jobs@2025-01-01' = if (deployValidatedJobs) {
  name: validationAnalystJobName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationAnalystIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
  ]
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'analyst'
  })
  properties: {
    configuration: {
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          identity: validationImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      replicaRetryLimit: 0
      replicaTimeout: 900
      triggerType: 'Manual'
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            '-m'
            'scripts.azure_staging_validator'
            '--pretty'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_VALIDATION_API_URL'
              value: 'https://${containerApp!.properties.configuration.ingress.fqdn}'
            }
            {
              name: 'SENTINEL_VALIDATION_AUDIENCE'
              value: 'api://${oidcAudience}'
            }
            {
              name: 'SENTINEL_VALIDATION_CLIENT_ID'
              value: validationAnalystIdentity!.properties.clientId
            }
            {
              name: 'SENTINEL_VALIDATION_ROLE'
              value: 'analyst'
            }
            {
              name: 'SENTINEL_VALIDATION_PHASE'
              value: 'analyst_prepare'
            }
            {
              name: 'SENTINEL_VALIDATION_RUN_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_VALIDATION_EXPECTED_SUBJECT'
              value: validationAnalystIdentity!.properties.principalId
            }
            {
              name: 'SENTINEL_VALIDATION_PEER_SUBJECT'
              value: validationApproverIdentity!.properties.principalId
            }
          ]
          image: validationContainerImage
          name: 'analyst-validator'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
    workloadProfileName: 'Consumption'
  }
}

resource validationApproverJob 'Microsoft.App/jobs@2025-01-01' = if (deployValidatedJobs) {
  name: validationApproverJobName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationApproverIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
  ]
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'approver'
  })
  properties: {
    configuration: {
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          identity: validationImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      replicaRetryLimit: 0
      replicaTimeout: 900
      triggerType: 'Manual'
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            '-m'
            'scripts.azure_staging_validator'
            '--pretty'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_VALIDATION_API_URL'
              value: 'https://${containerApp!.properties.configuration.ingress.fqdn}'
            }
            {
              name: 'SENTINEL_VALIDATION_AUDIENCE'
              value: 'api://${oidcAudience}'
            }
            {
              name: 'SENTINEL_VALIDATION_CLIENT_ID'
              value: validationApproverIdentity!.properties.clientId
            }
            {
              name: 'SENTINEL_VALIDATION_ROLE'
              value: 'approver'
            }
            {
              name: 'SENTINEL_VALIDATION_PHASE'
              value: 'approver_approve'
            }
            {
              name: 'SENTINEL_VALIDATION_RUN_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_VALIDATION_EXPECTED_SUBJECT'
              value: validationApproverIdentity!.properties.principalId
            }
            {
              name: 'SENTINEL_VALIDATION_PEER_SUBJECT'
              value: validationAnalystIdentity!.properties.principalId
            }
          ]
          image: validationContainerImage
          name: 'approver-validator'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
    workloadProfileName: 'Consumption'
  }
}

resource validationServiceBusJob 'Microsoft.App/jobs@2025-01-01' = if (deployValidatedJobs) {
  name: validationServiceBusJobName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationServiceBusReceiverIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    serviceBusPrivateDnsGroup
    validationAcrPull
    validationServiceBusReceiver
  ]
  tags: union(tags, {
    purpose: 'service-bus-receiver-validation'
  })
  properties: {
    configuration: {
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          identity: validationImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      replicaRetryLimit: 0
      replicaTimeout: 900
      triggerType: 'Manual'
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            '-m'
            'scripts.azure_live_gate_harness'
            'service-bus'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_SERVICE_BUS_NAMESPACE'
              value: '${serviceBus.name}.servicebus.windows.net'
            }
            {
              name: 'SENTINEL_SERVICE_BUS_QUEUE'
              value: governanceQueue.name
            }
            {
              name: 'SENTINEL_AZURE_CLIENT_ID'
              value: validationServiceBusReceiverIdentity!.properties.clientId
            }
            {
              name: 'SENTINEL_GATE_MESSAGE_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_SESSION_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_PAYLOAD_SHA256'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_SETTLEMENT'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_FROM_DEAD_LETTER'
              value: 'false'
            }
          ]
          image: validationContainerImage
          name: 'service-bus-validator'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
    workloadProfileName: 'Consumption'
  }
}

resource validationSourceDatabaseJob 'Microsoft.App/jobs@2025-01-01' = if (deployValidatedJobs) {
  name: validationSourceDatabaseJobName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationSourceDatabaseIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
    validationSourceDatabaseSecretReader
    vaultPrivateDnsGroup
  ]
  tags: union(tags, {
    purpose: 'source-postgresql-validation'
  })
  properties: {
    configuration: {
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          identity: validationImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      replicaRetryLimit: 0
      replicaTimeout: 900
      secrets: [
        {
          identity: validationSourceDatabaseIdentity.id
          keyVaultUrl: databaseUrlSecret.properties.secretUriWithVersion
          name: 'source-database-url'
        }
        {
          name: 'evidence-hmac-key'
          value: validationEvidenceHmacKey
        }
      ]
      triggerType: 'Manual'
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            '-m'
            'scripts.azure_live_gate_harness'
            'postgres-snapshot'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_RESTORE_DATABASE_URL'
              secretRef: 'source-database-url'
            }
            {
              name: 'SENTINEL_GATE_SYNTHETIC_PREFIX'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_FINDING_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_EXPECTED_TARGET_RESOURCE_ID'
              value: postgres.id
            }
            {
              name: 'SENTINEL_GATE_EXPECTED_TARGET_HOSTNAME'
              value: toLower(postgres.properties.fullyQualifiedDomainName)
            }
            {
              name: 'SENTINEL_GATE_EVIDENCE_HMAC_KEY'
              secretRef: 'evidence-hmac-key'
            }
          ]
          image: validationContainerImage
          name: 'source-database-validator'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
    workloadProfileName: 'Consumption'
  }
}

resource validationRestoredDatabaseJob 'Microsoft.App/jobs@2025-01-01' = if (deployValidatedRestoreJob) {
  name: validationRestoredDatabaseJobName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationRestoredDatabaseIdentity.id}': {}
    }
  }
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
  ]
  tags: union(tags, {
    purpose: 'restored-postgresql-validation'
  })
  properties: {
    configuration: {
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          identity: validationImagePullIdentity.id
          server: registry.properties.loginServer
        }
      ]
      replicaRetryLimit: 0
      replicaTimeout: 900
      secrets: [
        {
          name: 'restored-database-url'
          value: restoredDatabaseUrl
        }
        {
          name: 'evidence-hmac-key'
          value: validationEvidenceHmacKey
        }
      ]
      triggerType: 'Manual'
    }
    environmentId: containerEnvironment.id
    template: {
      containers: [
        {
          args: [
            '-m'
            'scripts.azure_live_gate_harness'
            'postgres-snapshot'
          ]
          command: [
            'python'
          ]
          env: [
            {
              name: 'SENTINEL_RESTORE_DATABASE_URL'
              secretRef: 'restored-database-url'
            }
            {
              name: 'SENTINEL_GATE_SYNTHETIC_PREFIX'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_FINDING_ID'
              value: 'REQUIRED_AT_START'
            }
            {
              name: 'SENTINEL_GATE_EXPECTED_TARGET_RESOURCE_ID'
              value: restoredPostgres!.id
            }
            {
              name: 'SENTINEL_GATE_EXPECTED_TARGET_HOSTNAME'
              value: toLower(restoredPostgres!.properties.fullyQualifiedDomainName)
            }
            {
              name: 'SENTINEL_GATE_EVIDENCE_HMAC_KEY'
              secretRef: 'evidence-hmac-key'
            }
          ]
          image: validationContainerImage
          name: 'restored-database-validator'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
    workloadProfileName: 'Consumption'
  }
}

resource availabilityAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (deployValidatedMonitoring) {
  name: availabilityAlertName
  location: 'global'
  tags: tags
  properties: {
    actions: empty(monitoringActionGroupResourceId) ? [] : [
      {
        actionGroupId: monitoringActionGroupResourceId
      }
    ]
    autoMitigate: true
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          criterionType: 'StaticThresholdCriterion'
          metricName: 'Replicas'
          metricNamespace: 'Microsoft.App/containerApps'
          name: 'NoRunningReplicas'
          operator: 'LessThan'
          threshold: 1
          timeAggregation: 'Average'
        }
      ]
    }
    description: 'SentinelGRC staging has no running Container Apps replicas.'
    enabled: true
    evaluationFrequency: 'PT1M'
    scopes: [
      containerApp.id
    ]
    severity: 0
    targetResourceRegion: location
    targetResourceType: 'Microsoft.App/containerApps'
    windowSize: 'PT5M'
  }
}

resource outboxHealthAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (deployValidatedMonitoring) {
  name: outboxHealthAlertName
  location: location
  kind: 'LogAlert'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${monitoringQueryIdentity!.id}': {}
    }
  }
  dependsOn: [
    containerEnvironmentDiagnostics
    monitoringQueryReader
  ]
  tags: tags
  properties: {
    actions: {
      actionGroups: empty(monitoringActionGroupResourceId) ? [] : [
        monitoringActionGroupResourceId
      ]
    }
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
    criteria: {
      allOf: [
        {
          failingPeriods: {
            minFailingPeriodsToAlert: 1
            numberOfEvaluationPeriods: 1
          }
          operator: 'GreaterThan'
          query: '''
ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "${publisherAppName}"
| where ContainerName_s == "outbox-publisher"
| extend payload = parse_json(Log_s)
| where toint(payload.dead) > 0 or toint(payload.retry) > 0 or toint(payload.stale) > 0
'''
          threshold: 0
          timeAggregation: 'Count'
        }
      ]
    }
    description: 'SentinelGRC outbox publisher reported dead, retrying, or stale delivery work.'
    displayName: 'SentinelGRC staging outbox delivery health'
    enabled: true
    evaluationFrequency: 'PT5M'
    scopes: [
      logAnalytics.id
    ]
    severity: 1
    skipQueryValidation: false
    windowSize: 'PT5M'
  }
}

module acrPull 'acr-pull-role.bicep' = {
  name: '${deployment().name}-acr-pull'
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
  params: {
    principalId: runtimeImagePullIdentity.properties.principalId
    registryName: containerRegistryName
  }
}

module validationAcrPull 'acr-pull-role.bicep' = if (deployValidatedJobs) {
  name: '${deployment().name}-validation-acr-pull'
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
  params: {
    principalId: validationImagePullIdentity!.properties.principalId
    registryName: containerRegistryName
  }
}

output deploymentMode string = deployValidatedApplication ? 'infrastructure-and-application' : 'infrastructure-only'
output managedIdentityResourceId string = appIdentity.id
output runtimeImagePullIdentityResourceId string = runtimeImagePullIdentity.id
output publisherIdentityResourceId string = publisherIdentity.id
output validationImagePullIdentityResourceId string = deployValidatedJobs ? validationImagePullIdentity.id : ''
output validationAnalystIdentityResourceId string = deployValidatedJobs ? validationAnalystIdentity.id : ''
output validationApproverIdentityResourceId string = deployValidatedJobs ? validationApproverIdentity.id : ''
output validationServiceBusReceiverIdentityResourceId string = deployValidatedJobs ? validationServiceBusReceiverIdentity.id : ''
output validationSourceDatabaseIdentityResourceId string = deployValidatedJobs ? validationSourceDatabaseIdentity.id : ''
output validationRestoredDatabaseIdentityResourceId string = deployValidatedRestoreJob ? validationRestoredDatabaseIdentity.id : ''
output validationAnalystJobResourceId string = deployValidatedJobs ? validationAnalystJob.id : ''
output validationApproverJobResourceId string = deployValidatedJobs ? validationApproverJob.id : ''
output validationServiceBusJobResourceId string = deployValidatedJobs ? validationServiceBusJob.id : ''
output validationSourceDatabaseJobResourceId string = deployValidatedJobs ? validationSourceDatabaseJob.id : ''
output validationRestoredDatabaseJobResourceId string = deployValidatedRestoreJob ? validationRestoredDatabaseJob.id : ''
output monitoringQueryIdentityResourceId string = deployValidatedMonitoring ? monitoringQueryIdentity.id : ''
output availabilityAlertResourceId string = deployValidatedMonitoring ? availabilityAlert.id : ''
output outboxHealthAlertResourceId string = deployValidatedMonitoring ? outboxHealthAlert.id : ''
output containerAppResourceId string = deployValidatedApplication ? containerApp.id : ''
output outboxPublisherAppResourceId string = deployValidatedApplication ? outboxPublisherApp.id : ''
output containerEnvironmentResourceId string = containerEnvironment.id
output postgresServerName string = postgres.name
output evidenceStorageAccountName string = storage.name
output serviceBusNamespaceName string = serviceBus.name
output keyVaultResourceId string = keyVault.id
