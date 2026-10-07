targetScope = 'resourceGroup'

@description('A dedicated, disposable AKS cluster. Never point this deployment at an existing cluster.')
param clusterName string
param location string = resourceGroup().location
param kubernetesVersion string
param nodeVmSize string
@description('The authenticated lab operator, granted Kubernetes administration on this cluster only.')
param operatorObjectId string
@description('Existing tenant ID; no new directory objects are created by this template.')
param tenantId string
@description('A narrowly scoped operator egress CIDR. Reject empty values and 0.0.0.0/0 before deployment.')
param operatorCidr string
@description('Verified role definition ID for Azure Kubernetes Service RBAC Cluster Admin.')
param clusterAdminRoleId string
param experimentId string
param expiresUtc string

resource aks 'Microsoft.ContainerService/managedClusters@2025-05-01' = {
  name: clusterName
  location: location
  tags: {
    experiment: experimentId
    purpose: 'kspm-controller-scope'
    expiresUtc: expiresUtc
  }
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: clusterName
    kubernetesVersion: kubernetesVersion
    enableRBAC: true
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      tenantID: tenantId
    }
    apiServerAccessProfile: {
      authorizedIPRanges: [operatorCidr]
    }
    agentPoolProfiles: [
      {
        name: 'system'
        count: 2
        vmSize: nodeVmSize
        osType: 'Linux'
        osSKU: 'AzureLinux'
        osDiskType: 'Managed'
        osDiskSizeGB: 64
        mode: 'System'
        type: 'VirtualMachineScaleSets'
        enableAutoScaling: false
        maxPods: 30
        upgradeSettings: {
          maxSurge: '1'
        }
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.0.0.0/16'
      dnsServiceIP: '10.0.0.10'
      outboundType: 'loadBalancer'
      loadBalancerSku: 'standard'
    }
  }
}

resource operatorAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aks.id, operatorObjectId, clusterAdminRoleId)
  scope: aks
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', clusterAdminRoleId)
  }
}

output clusterId string = aks.id
output nodeResourceGroup string = aks.properties.nodeResourceGroup
