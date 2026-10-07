targetScope = 'resourceGroup'

param experimentId string
param expiresUtc string
param contributorRoleId string

var groupUri = uri(environment().resourceManager, '${resourceGroup().id}?api-version=2021-04-01')

resource cleanup 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'kspm-expiry-cleanup'
  location: resourceGroup().location
  identity: { type: 'SystemAssigned' }
  tags: {
    experiment: experimentId
    purpose: 'kspm-controller-scope'
    expiresUtc: expiresUtc
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        Expiry: {
          type: 'Recurrence'
          recurrence: {
            frequency: 'Hour'
            interval: 1
            startTime: expiresUtc
          }
        }
      }
      actions: {
        Read_owned_group: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: groupUri
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: environment().resourceManager
            }
          }
          runAfter: {}
        }
        Verify_ownership_and_deadline: {
          type: 'If'
          expression: '@and(equals(toLower(body(\'Read_owned_group\')?[\'id\']),toLower(\'${resourceGroup().id}\')),equals(body(\'Read_owned_group\')?[\'tags\']?[\'experiment\'],\'${experimentId}\'),equals(body(\'Read_owned_group\')?[\'tags\']?[\'purpose\'],\'kspm-controller-scope\'),equals(body(\'Read_owned_group\')?[\'tags\']?[\'expiresUtc\'],\'${expiresUtc}\'),greaterOrEquals(ticks(utcNow()),ticks(\'${expiresUtc}\')))'
          actions: {
            Delete_only_owned_group: {
              type: 'Http'
              operationOptions: 'DisableAsyncPattern'
              inputs: {
                method: 'DELETE'
                uri: groupUri
                authentication: {
                  type: 'ManagedServiceIdentity'
                  audience: environment().resourceManager
                }
              }
              runAfter: {}
            }
          }
          else: { actions: {} }
          runAfter: { Read_owned_group: ['Succeeded'] }
        }
      }
      outputs: {}
    }
  }
}

resource cleanupPermission 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, cleanup.id, contributorRoleId)
  properties: {
    principalId: cleanup.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', contributorRoleId)
  }
}

output cleanupId string = cleanup.id
output scheduledUtc string = expiresUtc
