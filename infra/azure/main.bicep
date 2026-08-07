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

@description('Deploy the Container App only after the digest-pinned image exists in ACR.')
param deployApplication bool = false

@description('Deploy role-isolated manual staging validation jobs after the private application exists.')
param deployValidationJobs bool = false

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
var validationImagePullIdentityName = '${baseName}-validation-pull-id'
var validationAnalystIdentityName = '${baseName}-validation-analyst-id'
var validationApproverIdentityName = '${baseName}-validation-approver-id'
var validationAnalystJobName = '${baseName}-analyst-validation'
var validationApproverJobName = '${baseName}-approver-validation'
var availabilityAlertName = '${baseName}-no-replicas'
var outboxHealthAlertName = '${baseName}-outbox-health'
var workspaceName = '${baseName}-logs'
var appInsightsName = '${baseName}-appi'
var environmentResourceName = '${baseName}-cae'
var appName = '${baseName}-api'
var databaseName = 'sentinelgrc'
var storageAccountName = take('${compactName}data', 24)
var keyVaultName = take('${baseName}-kv', 24)
var serviceBusName = take('${baseName}-bus', 50)
var serviceBusQueueName = 'governance-outbox'
var evidenceContainerName = 'evidence'
var auditContainerName = 'audit-archive'
var databaseSecretName = 'sentinel-database-url'
var imageDigestPinned = contains(containerImage, '@sha256:') && length(last(split(containerImage, '@sha256:'))) == 64

var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)
var storageBlobContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var serviceBusSenderRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
)
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

resource containerSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: containerSubnetName
  parent: vnet
}

resource databaseSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: databaseSubnetName
  parent: vnet
}

resource privateEndpointSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: privateEndpointSubnetName
  parent: vnet
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
  name: '${baseName}-pg-link'
  parent: postgresPrivateDns
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource blobDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: '${baseName}-blob-link'
  parent: blobPrivateDns
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource vaultDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: '${baseName}-vault-link'
  parent: vaultPrivateDns
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource serviceBusDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: '${baseName}-bus-link'
  parent: serviceBusPrivateDns
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource acrDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: '${baseName}-acr-link'
  parent: acrPrivateDns
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

resource validationImagePullIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: validationImagePullIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-validation-image-pull'
  })
}

resource validationAnalystIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: validationAnalystIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'analyst'
  })
}

resource validationApproverIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: validationApproverIdentityName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'approver'
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

resource containerEnvironmentDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (deployApplication && deployMonitoringAlerts && imageDigestPinned) {
  name: 'sentinelgrc-staging-logs'
  scope: containerEnvironment
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
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
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
  dependsOn: [
    postgresDnsLink
  ]
}

resource governanceDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  name: databaseName
  parent: postgres
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: storage
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
  name: evidenceContainerName
  parent: blobService
  properties: {
    publicAccess: 'None'
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: auditContainerName
  parent: blobService
  properties: {
    immutableStorageWithVersioning: {
      enabled: true
    }
    publicAccess: 'None'
  }
}

resource auditImmutabilityPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  name: 'default'
  parent: auditContainer
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
  name: databaseSecretName
  parent: keyVault
  properties: {
    value: 'postgresql://${databaseAdministratorLogin}:${uriComponent(databaseAdministratorPassword)}@${postgres.properties.fullyQualifiedDomainName}:5432/${databaseName}?sslmode=require'
  }
  dependsOn: [
    governanceDatabase
  ]
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: serviceBusName
  location: location
  tags: tags
  sku: {
    capacity: 1
    name: 'Premium'
    tier: 'Premium'
  }
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    premiumMessagingPartitions: 1
    publicNetworkAccess: 'Disabled'
    zoneRedundant: false
  }
}

resource governanceQueue 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  name: serviceBusQueueName
  parent: serviceBus
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
  name: 'default'
  parent: blobPrivateEndpoint
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
  name: 'default'
  parent: vaultPrivateEndpoint
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
  name: 'default'
  parent: serviceBusPrivateEndpoint
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

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: containerRegistryName
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
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
  name: 'default'
  parent: acrPrivateEndpoint
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

module acrPull 'acr-pull-role.bicep' = {
  name: '${deployment().name}-acr-pull'
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
  params: {
    principalId: appIdentity.properties.principalId
    registryName: containerRegistryName
  }
}

module validationAcrPull 'acr-pull-role.bicep' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: '${deployment().name}-validation-acr-pull'
  scope: resourceGroup(containerRegistrySubscriptionId, containerRegistryResourceGroup)
  params: {
    principalId: validationImagePullIdentity!.properties.principalId
    registryName: containerRegistryName
  }
}

resource keyVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appIdentity.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

resource evidenceBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceContainer.id, appIdentity.id, storageBlobContributorRoleId)
  scope: evidenceContainer
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobContributorRoleId
  }
}

resource auditBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(auditContainer.id, appIdentity.id, storageBlobContributorRoleId)
  scope: auditContainer
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobContributorRoleId
  }
}

resource serviceBusSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(governanceQueue.id, appIdentity.id, serviceBusSenderRoleId)
  scope: governanceQueue
  properties: {
    principalId: appIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: serviceBusSenderRoleId
  }
}

resource containerApp 'Microsoft.App/containerApps@2025-01-01' = if (deployApplication && imageDigestPinned) {
  name: appName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${appIdentity.id}': {}
    }
  }
  properties: {
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        allowInsecure: false
        external: false
        targetPort: 8080
        transport: 'auto'
      }
      registries: [
        {
          identity: appIdentity.id
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
              value: appIdentity.properties.clientId
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
  dependsOn: [
    acrPrivateDnsGroup
    acrPull
    auditBlobContributor
    blobPrivateDnsGroup
    keyVaultSecretsUser
    serviceBusPrivateDnsGroup
    serviceBusSender
    vaultPrivateDnsGroup
  ]
}

resource validationAnalystJob 'Microsoft.App/jobs@2025-01-01' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: validationAnalystJobName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'analyst'
  })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationAnalystIdentity.id}': {}
    }
  }
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
          ]
          image: containerImage
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
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
  ]
}

resource validationApproverJob 'Microsoft.App/jobs@2025-01-01' = if (deployApplication && deployValidationJobs && imageDigestPinned) {
  name: validationApproverJobName
  location: location
  tags: union(tags, {
    purpose: 'staging-lifecycle-validation'
    sentinelRole: 'approver'
  })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${validationImagePullIdentity.id}': {}
      '${validationApproverIdentity.id}': {}
    }
  }
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
          ]
          image: containerImage
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
  dependsOn: [
    acrPrivateDnsGroup
    validationAcrPull
  ]
}

resource availabilityAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = if (deployApplication && deployMonitoringAlerts && imageDigestPinned) {
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

resource outboxHealthAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (deployApplication && deployMonitoringAlerts && imageDigestPinned) {
  name: outboxHealthAlertName
  location: location
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
          dimensions: []
          failingPeriods: {
            minFailingPeriodsToAlert: 1
            numberOfEvaluationPeriods: 1
          }
          operator: 'GreaterThan'
          query: '''
ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "${appName}"
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
  dependsOn: [
    containerEnvironmentDiagnostics
  ]
}

output deploymentMode string = deployApplication
  ? (imageDigestPinned ? 'infrastructure-and-application' : 'application-blocked-invalid-image')
  : 'infrastructure-only'
output managedIdentityResourceId string = appIdentity.id
output validationImagePullIdentityResourceId string = deployApplication && deployValidationJobs && imageDigestPinned ? validationImagePullIdentity.id : ''
output validationAnalystIdentityResourceId string = deployApplication && deployValidationJobs && imageDigestPinned ? validationAnalystIdentity.id : ''
output validationApproverIdentityResourceId string = deployApplication && deployValidationJobs && imageDigestPinned ? validationApproverIdentity.id : ''
output validationAnalystJobResourceId string = deployApplication && deployValidationJobs && imageDigestPinned ? validationAnalystJob.id : ''
output validationApproverJobResourceId string = deployApplication && deployValidationJobs && imageDigestPinned ? validationApproverJob.id : ''
output availabilityAlertResourceId string = deployApplication && deployMonitoringAlerts && imageDigestPinned ? availabilityAlert.id : ''
output outboxHealthAlertResourceId string = deployApplication && deployMonitoringAlerts && imageDigestPinned ? outboxHealthAlert.id : ''
output containerAppResourceId string = deployApplication && imageDigestPinned ? containerApp.id : ''
output containerEnvironmentResourceId string = containerEnvironment.id
output postgresServerName string = postgres.name
output evidenceStorageAccountName string = storage.name
output serviceBusNamespaceName string = serviceBus.name
output keyVaultResourceId string = keyVault.id
