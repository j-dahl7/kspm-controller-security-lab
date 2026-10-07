"""Prepare private deployment parameters. This command creates no Azure resources."""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
import uuid

from collect_assessments import GUID, az_json, ensure_private_directory


def validate_operator_cidr(value):
    network = ipaddress.ip_network(value, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError('Use the operator public IPv4 address with /32; broad ranges are refused')
    return str(network)


def parameters(subscription, tenant, operator, role, cidr, experiment, expires):
    for value in [subscription, tenant, operator, role]:
        if not GUID.fullmatch(value):
            raise ValueError('Expected a verified GUID')
    cidr = validate_operator_cidr(cidr)
    values = {'clusterName': 'nls-kspm-scope', 'location': 'eastus',
              'kubernetesVersion': '1.35.8', 'nodeVmSize': 'Standard_D4as_v4',
              'operatorObjectId': operator, 'tenantId': tenant,
              'operatorCidr': cidr, 'clusterAdminRoleId': role,
              'experimentId': experiment, 'expiresUtc': expires}
    return {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#',
            'contentVersion': '1.0.0.0', 'parameters': {key: {'value': value} for key, value in values.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--operator-cidr', required=True)
    parser.add_argument('--location', default='northcentralus')
    parser.add_argument('--hours', type=int, choices=range(1, 25), default=4,
                        help='Explicit cleanup deadline in hours (1-24); budget separately.')
    args = parser.parse_args()
    if not GUID.fullmatch(args.subscription):
        parser.error('subscription must be a GUID')
    validate_operator_cidr(args.operator_cidr)
    account = az_json(['account', 'show', '--subscription', args.subscription])
    if account['id'].lower() != args.subscription.lower():
        raise ValueError('Wrong subscription')
    operator = az_json(['rest', '--method', 'get', '--subscription', args.subscription,
                       '--url', 'https://graph.microsoft.com/v1.0/me?$select=id'])
    roles = az_json(['role', 'definition', 'list', '--subscription', args.subscription,
                     '--name', 'Azure Kubernetes Service RBAC Cluster Admin'])
    if len(roles) != 1:
        raise ValueError('Cannot uniquely resolve the cluster-scoped operator role')
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=args.hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
    experiment = 'kspm-' + uuid.uuid4().hex[:12]
    body = parameters(args.subscription, account['tenantId'], operator['id'], roles[0]['name'],
                      args.operator_cidr, experiment, expires)
    if not re.fullmatch(r'[a-z0-9]{3,30}', args.location):
        raise ValueError('Unexpected Azure region name')
    body['parameters']['location']['value'] = args.location
    folder = ensure_private_directory()
    prefix = now.strftime('%Y%m%dT%H%M%S%fZ')
    path = folder / f'{prefix}.parameters.local.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(body, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'parametersFile': path.name, 'resourceGroup': 'nls-kspm-scope-20261007',
                      'experimentId': experiment, 'expiresUtc': expires,
                      'deploysResources': False, 'cleanupScheduled': False}))


if __name__ == '__main__':
    main()
