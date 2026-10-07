# Defender for Cloud: controller-scoped KSPM evidence lab

Status on October 7, 2026: deployed on AKS 1.35.8 in North Central US. The live pod-replacement comparison is published in `results/pod-replacement-comparison.json`. **No live KSPM finding has yet been observed.** The Kubernetes result is not a claim about Defender finding stability or remediation.

This experiment tests the October 5, 2026 change from running-container scope to workload-controller scope for Kubernetes misconfiguration recommendations. It is separate from admission control, image CVEs, runtime malware, and Azure Policy workload-hardening assessments.

## Question

When replaceable pods change, what happens to the recommendation's identity, target resource, cardinality and remediation status? Do consumers that deduplicate tickets or match exceptions by resource retain the intended scope?

The release announcement establishes the scope change. It does not establish the answers to those questions.

## Tested deployment

- Existing primary lab subscription and its existing Defender CSPM / Containers settings.
- Dedicated resource group `nls-kspm-scope-20261007` and cluster `nls-kspm-scope` in North Central US. East US rejected cluster creation due to regional AKS capacity; that failed attempt created no cluster.
- Free AKS control-plane tier; two `Standard_D4as_v4` nodes; Azure Linux; Kubernetes 1.35.8. This follows the current system-pool guidance (two nodes, at least four vCPUs per node).
- Entra authentication and Azure RBAC, local administrator accounts disabled; cluster-only administration for the current operator.
- API access restricted to the operator's explicitly supplied egress CIDR. Defender uses its documented Trusted Access path.
- No application Service or ingress. The namespace has restricted Pod Security admission and a default-deny NetworkPolicy.
- One Deployment with two replicas, using the digest-pinned Kubernetes pause image. The only intentional security configuration weakness is a writable root filesystem. The test container does not run commands, use credentials, expose a port, or access host resources.
- No new subscription-wide Defender configuration, policy assignment, Sentinel workspace, Azure Policy add-on, or Helm sensor is required by this package. Existing Azure policies may provision components; inspect their results rather than disabling them.

The selected SKU had available quota and no location restrictions in North Central US at deployment. Always query your own subscription's SKU restrictions, quotas and supported Kubernetes versions. Successful ARM validation does not guarantee regional control-plane capacity.

## What worked in the live test

At 20:33:02 UTC the deployment had two ready pods. After deleting one UID-verified test pod, the 20:55:54 UTC capture had two ready pods: one original and one replacement. The Deployment object and active ReplicaSet were unchanged. Both pods still matched the original image and `readOnlyRootFilesystem: false` template. The timestamps delimit observations; the interval includes investigation time and is not replacement latency.

The comparator verified the source hashes, ownership chain, readiness and scope before producing the public comparison. Raw identifiers and captures remain private. The comparison file contains no subscription ID, cluster endpoint, raw Kubernetes UID, or credential.

Defender access was checked separately. The existing Defender security operator and its subscription role were verified. The new cluster initially had no Trusted Access binding, so we used Microsoft's documented manual binding path. Both the Azure binding and in-cluster read-only role binding were observed. That establishes access, not completion of a discovery scan.

## Sequence and evidence gates

| Phase | Change | Evidence required before advancing |
|---|---|---|
| Preflight | None | Plan/discovery configuration, cluster version/SKU availability and permissions |
| Baseline | Apply the four named resource manifests | Healthy workload, trusted discovery connection, and a matching live KSPM assessment |
| Scale | Two replicas to four | New Kubernetes snapshot and a refreshed matching assessment |
| Roll | Replace the pods without changing the security setting | New Pod UIDs and refreshed matching assessment; stable controller UID checked separately |
| Remediate | Apply the single-field read-only patch | New Deployment generation and observed assessment status after reconciliation |
| Cleanup | Delete the disposable group after saving evidence | Verify the group and managed node group are absent |

For the Defender comparison, do not run these phases back-to-back while waiting for the first finding. Agentless changes can take up to 24 hours to reach security graph surfaces; this is not a published KSPM recommendation SLA. A capture made after a mutation may still represent older state. Preserve both capture and assessment timestamps. End inconclusively at the time/budget boundary if necessary.

The separate Kubernetes pod-replacement control was run while the Defender baseline was pending. It preserved the two-replica workload and its security configuration. It does not substitute for a before/after Defender comparison.

## Reproduce the isolated environment

Requires Python 3.12+, Azure CLI, Bicep, native `kubectl`, `kubelogin`, and permissions to create an AKS cluster and its scoped role assignments. The PowerShell example requires PowerShell 7.5+ so date strings remain strings. Set your own public operator IPv4 /32. Confirm the applicable Defender plan and `AgentlessDiscoveryForKubernetes` are already enabled; this lab never enables a subscription-wide plan for you.

```powershell
$sub = '<subscription-guid>'
$cidr = '<your-public-ipv4>/32'
python scripts/prepare_run.py --subscription $sub --operator-cidr $cidr --location northcentralus --hours 4
# Use the exact new filename printed by the command:
$parameterFile = 'private/<timestamp>.parameters.local.json'
$p = Get-Content $parameterFile -Raw | ConvertFrom-Json -DateKind String
$experiment = $p.parameters.experimentId.value
$expiry = $p.parameters.expiresUtc.value
$rg = 'nls-kspm-scope-20261007'

if ((az group exists --name $rg --subscription $sub -o tsv) -ne 'false') {
    throw 'Choose a clean subscription or remove only your previous verified lab; never overwrite an existing group.'
}
az group create --name $rg --location northcentralus --subscription $sub --tags "experiment=$experiment" 'purpose=kspm-controller-scope' "expiresUtc=$expiry"
az bicep build --file infra/main.bicep --outfile infra/main.json
az bicep build --file infra/cleanup.bicep --outfile infra/cleanup.json
az deployment group create --name kspm-cleanup --resource-group $rg --subscription $sub --template-file infra/cleanup.json --parameters "experimentId=$experiment" "expiresUtc=$expiry" 'contributorRoleId=b24988ac-6180-42a0-ab88-20f7382dd24c'
az deployment group create --name kspm-lab --resource-group $rg --subscription $sub --template-file infra/main.json --parameters "@$parameterFile"
az aks get-credentials --name nls-kspm-scope --resource-group $rg --subscription $sub --file private/kubeconfig --format exec
kubelogin convert-kubeconfig -l azurecli --kubeconfig private/kubeconfig
```

Check each command's exit code before proceeding. The Azure-hosted cleanup workflow starts at the explicit UTC deadline. It checks group identity, experiment/purpose tags and deadline before deleting only its own group; it uses a managed identity scoped to that group. A successful deployment of the workflow does not establish a completed cleanup. Verify the final deletion of the cluster and managed node group.

If automatic discovery access has not appeared, first verify the existing `DefenderCSPMSecurityOperator` and its assigned role, then follow the [documented Trusted Access recovery procedure](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#what-do-i-do-if-i-have-locked-resource-groups-subscriptions-or-clusters). Bind only `Microsoft.Security/pricings/microsoft-defender-operator` to this lab cluster using the verified security-operator resource. Do not add the policy-writing or network-policy-writing roles for this posture experiment. The binding is not a scan-now command.

## Evidence collection

`scripts/collect_assessments.py` calls the documented read-only ARM assessment-list API. It captures all pages, rejects pagination URLs outside the exact subscription assessment collection, and records a SHA-256 digest. Raw subscription data is saved only under ignored, access-restricted `private/`.

```text
python scripts/collect_assessments.py --subscription <subscription-guid> --cluster-id <exact-cluster-resource-id> --phase baseline
```

`scripts/collect_arg.py` independently collects the same documented assessment resource type through Azure Resource Graph. It follows `$skipToken`, rejects unaccounted truncation, and scopes the request to the supplied subscription. It accepts the same arguments as the ARM collector. These are separate data surfaces; compare capture times before interpreting different total counts.

The candidate filter is deliberately broad. Its count is **not** the measured finding count. Manually confirm the recommendation type, cluster, namespace, workload and target fields before selecting the evidence set. Both collectors report schema paths from returned JSON but assume no new controller field or assessment ID. Read-only requests retry transient connection resets; writes are never automatically retried.

For each phase, capture Kubernetes Deployments, ReplicaSets, Pods, namespace policy, UTC time and the exact applied manifest hash. Preserve owner-reference UIDs, not only names. Keep kubeconfig and unredacted JSON private. Do not interpret an empty assessment result as health or successful remediation.

Only derive a workload-owner ARG query after inspecting live assessment fields. Until then, `queries/discover-assessments.kql` is a schema-discovery query, not a finished controller resolver.

```powershell
$clusterId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.ContainerService/managedClusters/nls-kspm-scope"
python scripts/capture_kubernetes.py --subscription $sub --cluster-id $clusterId --experiment-id $experiment --kubeconfig private/kubeconfig --phase baseline
python scripts/collect_assessments.py --subscription $sub --cluster-id $clusterId --phase baseline
python scripts/collect_arg.py --subscription $sub --cluster-id $clusterId --phase baseline
# After a separately captured intervention, use exact filenames:
python scripts/compare_captures.py --before private/<before>-kubernetes.json --after private/<after>-kubernetes.json --out results/<new-comparison>.json
```

The Kubernetes collector exits 0 only for a complete ready snapshot; exit 2 preserves incomplete rollout evidence; exit 1 means identity or collection failure. It checks the selected API hostname against Azure, then validates controller owner references by UID. The comparison helper requires intact hash sidecars, complete ready captures, matching scope and increasing UTC times. Its public output reports only selected observations and comparison counts, never a Defender verdict.

## Applying fixtures

Use a dedicated kubeconfig with an explicitly verified server/cluster context. Apply these files by exact name, in order:

1. `manifests/namespace.json`
2. `manifests/default-deny-networkpolicy.json`
3. `manifests/resource-quota.json`
4. `manifests/baseline-deployment.json`

Do not apply the entire directory. `harden-readonly.patch.json` is an RFC 6902 patch and must use `kubectl patch deployment kspm-scope-proof --namespace nls-kspm-controller-lab --type=json --patch-file manifests/harden-readonly.patch.json`. The patch tests the expected container before changing the filesystem setting.

## Validation

```text
python -m unittest discover -s tests -v
python -m unittest discover -s manifests/tests -v
az bicep build --file infra/main.bicep --outfile infra/main.json
```

October 7 local checks: 55 tests passed, and both Bicep templates compiled. The collectors and Kubernetes comparison also ran against the live lab. These results do not establish a Defender finding or clearance. See the dated verification record and public comparison for the measured scope.

## Time and costs

The two-node system pool uses Linux `Standard_D4as_v4`. Compute, disks, load balancing/public IP, Defender coverage and any telemetry are billable. Query prices for your chosen region and agreement. This run has an approved USD 50 allowance, with same-day cleanup scheduled for 00:15 UTC on October 8 (19:15 America/Chicago on October 7). This is an operating allowance, not an Azure-enforced billing cap or a measured invoice.

The Azure-hosted cleanup guard is deployed. A manual pre-deadline check read the owned group successfully and skipped deletion as expected. A tag alone does not enforce expiry. Verify the cleanup workflow and its scope before leaving any reproduction unattended.

Cleanup must bind the exact subscription, resource-group ID and experiment tag to the deployment receipt. Refuse an existing or mismatched group. Delete only this experiment's group, then verify both it and the AKS-managed node group are gone. Preserve existing subscription security plans and all other lab resources.

`scripts/prepare_run.py` prepares private ARM parameters from the signed-in operator and a public IPv4 /32. It creates no resources. `scripts/cleanup_lab.py` defaults to read-only planning and requires a deployment receipt plus its separately retained SHA-256 digest. It checks live identities, tags, the managed-node-group relationship, and unexpected resources. `--execute` requests deletion; a later read must confirm completion. Neither helper schedules cleanup by itself.

Receipt fields: `subscriptionId`, `resourceGroupId`, `clusterId`, `experimentId`, `nodeResourceGroupId`, and optional `clusterResourceUid` if returned by Azure. Create the receipt from successful live deployment outputs and record its digest in the authorized monitoring configuration. Never synthesize a receipt from guessed resource identities.

## Sources

- [October 5 scope-change announcement](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#kspm-misconfiguration-recommendations-moving-to-controller-level-scope-ga)
- [Discovery support matrix](https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-containers#security-posture-management-features)
- [Network access and Trusted Access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-network-access#azure-kubernetes-service-aks)
- [Discovery refresh FAQ](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#whats-the-refresh-interval-for-agentless-discovery-of-kubernetes)
- [Assessment-list API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-stable)
- [Individual assessment model](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Azure retail pricing API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
- [AKS system-pool restrictions](https://learn.microsoft.com/en-us/azure/aks/use-system-pools#system-and-user-node-pools)
