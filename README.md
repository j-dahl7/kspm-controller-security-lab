# Defender for Cloud: controller-scoped KSPM evidence lab

Status on October 7, 2026: tested on AKS 1.35.8 in North Central US. Live comparisons in `results/` document pod replacement, scaling, a template change, and replacement after hardening. **No live KSPM finding was observed during the bounded test.** The completed Kubernetes demonstration does not establish Defender finding stability or clearance. The experiment resource group and AKS-managed node group were both verified absent at approximately 21:37 UTC after manual cleanup.

This package pairs a reproducible Kubernetes ownership experiment with collection tools for evaluating the October 5, 2026 change to workload-controller scope in Defender recommendations. Kubernetes behavior and Defender assessment behavior require separate evidence. Neither is an admission-control, image-CVE, or runtime-malware test.

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
- One Deployment starting with two replicas and scaled to four, using the digest-pinned Kubernetes pause image. The only intentional security configuration weakness is a writable root filesystem. The test container does not run injected commands, use credentials, expose a port, or access host resources.
- No new subscription-wide Defender configuration, policy assignment, Sentinel workspace, Azure Policy add-on, or Helm sensor is required by this package. Existing Azure policies may provision components; inspect their results rather than disabling them.

The selected SKU had available quota and no location restrictions in North Central US at deployment. Always query your own subscription's SKU restrictions, quotas and supported Kubernetes versions. Successful ARM validation does not guarantee regional control-plane capacity.

## What worked in the live test

All times below are **October 7, 2026 UTC**, shown to the second. Linked artifacts retain fractional-second timestamps and hashes of the underlying captures.

| Experiment | Before → after capture | Observed Kubernetes result |
|---|---|---|
| [Initial pod replacement](results/pod-replacement-comparison.json) | 20:33:02 → 20:55:54 | Two ready replicas; one original pod retained, one replaced. Same Deployment and active ReplicaSet. The replacement still had `readOnlyRootFilesystem: false`. |
| [Scale](results/scale-comparison.json) | 21:22:02 → 21:22:53 | Two → four ready replicas; two original pods retained, two new. Same Deployment and active ReplicaSet. All four matched the original writable-root template. |
| [Template change](results/template-remediation-comparison.json) | 21:22:53 → 21:23:52 | Four → four ready replicas; four replacement pods and a new active ReplicaSet. Same Deployment UID. The template and all four pods had `readOnlyRootFilesystem: true`. |
| [Replacement after hardening](results/hardened-replacement-comparison.json) | 21:23:52 → 21:24:43 | Four ready replicas; three original pods retained, one replaced. Same Deployment and active ReplicaSet. All four retained the read-only setting. |

The requested image and observed image-ID set were unchanged in all four comparisons. The results establish controller identity, ready pause containers, and propagation of the selected configuration. We did **not** execute an application write-denial test. The timestamps delimit snapshots, not measured rollout or replacement latency, and do not establish continuous state between observations.

The comparator verified the source hashes, ownership chain, readiness and scope before producing the public comparison. Raw identifiers and captures remain private. The comparison file contains no subscription ID, cluster endpoint, raw Kubernetes UID, or credential.

Defender access was checked separately. The existing Defender security operator and its subscription role were verified. The new cluster initially had no Trusted Access binding, so we used Microsoft's documented manual binding path. Both the Azure binding and in-cluster read-only role binding were observed. That establishes access, not completion of a discovery scan.

## Two evidence tracks

The Kubernetes demonstration can finish even when Defender has not returned a finding. Choose the track before changing the workload:

| Capture phase | Kubernetes demonstration | Additional evidence for a Defender comparison |
|---|---|---|
| `baseline` | Two ready replicas with the original template | An actual matching KSPM assessment and its target fields |
| `scaled` | Scale to four; compare Pod UIDs and the active ReplicaSet | A refreshed assessment demonstrably representing the scaled workload |
| `remediated` | Patch the template to read-only; verify ready replacement pods | A subsequent service assessment; a Kubernetes setting is not Defender clearance |
| `rolled` | Replace one pod after hardening; verify the setting persists | A subsequent assessment before asserting finding identity or scope stability |

For the **Kubernetes track**, use the commands below and capture each ready state. For the **Defender track**, stop at baseline until a matching assessment exists, then wait for refreshed evidence between interventions. Do not perform rapid changes and retrospectively assign delayed service records to each phase. Agentless changes can take up to 24 hours to reach security graph surfaces; that is not a published KSPM recommendation SLA.

An empty Defender result is an observation limit, not healthy status. If the first finding never arrives within the time and budget, retain the completed Kubernetes comparisons and report the Defender experiment as unobserved. The earlier two-replica pod-replacement control in `results/` is separate from the reproduction sequence below.

## Reproduce the isolated environment

Requires Python 3.12+, Azure CLI, Bicep, native `kubectl`, `kubelogin`, and permissions to create an AKS cluster and its scoped role assignments. The PowerShell example requires PowerShell 7.5+ so date strings remain strings. Set your own public operator IPv4 /32. Confirm the applicable Defender plan and `AgentlessDiscoveryForKubernetes` are already enabled; this lab never enables a subscription-wide plan for you.

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Invoke-LabChecked {
    param([Parameter(Mandatory)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "Native command failed with exit code $LASTEXITCODE; stop here." }
}
# Put one native command in each checked block. Keep this PowerShell session
# for the later workload and capture examples.
$sub = '<subscription-guid>'
$cidr = '<your-public-ipv4>/32'
$prepared = (Invoke-LabChecked { python scripts/prepare_run.py --subscription $sub --operator-cidr $cidr --location northcentralus --hours 4 }) | ConvertFrom-Json
$parameterFile = Join-Path 'private' $prepared.parametersFile
$p = Get-Content -LiteralPath $parameterFile -Raw | ConvertFrom-Json -DateKind String
$experiment = $p.parameters.experimentId.value
$expiry = $p.parameters.expiresUtc.value
$rg = 'nls-kspm-scope-20261007'
$clusterName = 'nls-kspm-scope'
$clusterId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.ContainerService/managedClusters/$clusterName"
$kubeconfig = Join-Path (Resolve-Path 'private').Path 'kubeconfig'

if ((Invoke-LabChecked { az group exists --name $rg --subscription $sub -o tsv }) -ne 'false') {
    throw 'The named group already exists; do not adopt or overwrite it.'
}
if (Test-Path -LiteralPath $kubeconfig) { throw 'Use a new dedicated kubeconfig path.' }
Invoke-LabChecked { az group create --name $rg --location northcentralus --subscription $sub --tags "experiment=$experiment" 'purpose=kspm-controller-scope' "expiresUtc=$expiry" }
Invoke-LabChecked { az bicep build --file infra/main.bicep --outfile infra/main.json }
Invoke-LabChecked { az bicep build --file infra/cleanup.bicep --outfile infra/cleanup.json }
Invoke-LabChecked { az deployment group create --name kspm-cleanup --resource-group $rg --subscription $sub --template-file infra/cleanup.json --parameters "experimentId=$experiment" "expiresUtc=$expiry" 'contributorRoleId=b24988ac-6180-42a0-ab88-20f7382dd24c' }
Invoke-LabChecked { az deployment group create --name kspm-lab --resource-group $rg --subscription $sub --template-file infra/main.json --parameters "@$parameterFile" }
Invoke-LabChecked { az aks get-credentials --name $clusterName --resource-group $rg --subscription $sub --file $kubeconfig --format exec }
Invoke-LabChecked { kubelogin convert-kubeconfig -l azurecli --kubeconfig $kubeconfig }
```

The wrapper stops on nonzero native exit codes rather than continuing after a failed deployment or capture. An interrupted setup is not permission to rerun over an existing group; reconcile the recorded resources first. The Azure-hosted cleanup workflow starts at the explicit UTC deadline and checks group identity and ownership before deletion. Verify the final deletion of the cluster and managed node group; workflow deployment alone is not completed cleanup.

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

The Kubernetes collector exits 0 only for a complete ready snapshot; exit 2 preserves incomplete rollout evidence; exit 1 means identity or collection failure. It checks the selected API hostname against Azure, then validates controller owner references by UID. The comparison helper requires intact hash sidecars, complete ready captures, matching scope and increasing UTC times. Its public output reports only selected observations and comparison counts, never a Defender verdict.

## Run the Kubernetes demonstration

Run from the repository root using the variables and checked-command function above. Use the dedicated kubeconfig created for this cluster, not the default context. The following creates only the four named fixtures; applying the entire directory would incorrectly treat a JSON Patch document as a Kubernetes resource.

```powershell
$namespace = 'nls-kspm-controller-lab'
$deployment = 'kspm-scope-proof'
$existingNamespace = Invoke-LabChecked { kubectl --kubeconfig $kubeconfig get namespace $namespace --ignore-not-found --output name }
if ($existingNamespace) { throw 'The fixture namespace already exists; reconcile the previous run first.' }
foreach ($manifest in @('namespace.json', 'default-deny-networkpolicy.json', 'resource-quota.json', 'baseline-deployment.json')) {
    Invoke-LabChecked { kubectl --kubeconfig $kubeconfig apply --filename "manifests/$manifest" }
}
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace rollout status "deployment/$deployment" --timeout=300s }

function Save-LabSnapshot {
    param([ValidateSet('baseline','scaled','remediated','rolled')][string]$Phase)
    $receipt = (Invoke-LabChecked { python scripts/capture_kubernetes.py --subscription $sub --cluster-id $clusterId --experiment-id $experiment --kubeconfig $kubeconfig --phase $Phase }) | ConvertFrom-Json
    Join-Path 'private' $receipt.file
}
$baseline = Save-LabSnapshot baseline
$runStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
New-Item -ItemType Directory -Path 'results' -Force | Out-Null

# Two replicas to four; the security setting stays unchanged.
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace scale "deployment/$deployment" --current-replicas=2 --replicas=4 }
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace rollout status "deployment/$deployment" --timeout=300s }
$scaled = Save-LabSnapshot scaled
Invoke-LabChecked { python scripts/compare_captures.py --before $baseline --after $scaled --out "results/$runStamp-scale.json" }

# Change the owning template, then verify the resulting rollout.
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace patch deployment $deployment --type=json --patch-file manifests/harden-readonly.patch.json }
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace rollout status "deployment/$deployment" --timeout=300s }
$remediated = Save-LabSnapshot remediated
Invoke-LabChecked { python scripts/compare_captures.py --before $scaled --after $remediated --out "results/$runStamp-template-change.json" }
```

The RFC 6902 patch first tests that container zero is named `pause`, then sets only its `readOnlyRootFilesystem` field to `true`. Microsoft lists [immutable root filesystems](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container#immutable-read-only-root-filesystem-should-be-enforced-for-containers) in its recommendation catalog. That reference does not prove this lab received a new controller-scoped assessment. Here, `remediated` is a phase label for a Kubernetes configuration change, not a Defender verdict.

To check persistence after replacing one hardened pod, select it from the accepted capture and recheck its UID and the Deployment UID immediately before deletion:

```powershell
$proof = Get-Content -LiteralPath $remediated -Raw | ConvertFrom-Json -DateKind String
$targetPod = $proof.pods[0]
$currentPod = (Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace get pod $targetPod.metadata.name --output json }) | ConvertFrom-Json -DateKind String
$currentDeployment = (Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace get deployment $deployment --output json }) | ConvertFrom-Json -DateKind String
if ($currentPod.metadata.uid -ne $targetPod.metadata.uid -or $currentDeployment.metadata.uid -ne $proof.deployment.metadata.uid) {
    throw 'The selected Kubernetes objects changed; capture and review the new state before proceeding.'
}
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace delete pod $targetPod.metadata.name --wait=true --timeout=120s }
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace rollout status "deployment/$deployment" --timeout=300s }
$replaced = Save-LabSnapshot rolled
Invoke-LabChecked { python scripts/compare_captures.py --before $remediated --after $replaced --out "results/$runStamp-hardened-replacement.json" }
```

Run this isolated experiment without another operator changing its objects; the read-before-delete check is not an atomic UID precondition on deletion. If a capture exits 2, allow the workload to settle and repeat **only that capture**, then its comparison. Do not reapply the baseline manifest to “fix” a capture: that would reset replicas and the security setting. The comparison must show what was observed; no unchanged UID, replacement, or image invariant is assumed from the phase name.

For the separate Defender track, run both read-only collectors at each chosen phase, with no intervening workload changes while waiting for the corresponding service evidence:

```powershell
$phase = 'baseline' # Use the actual observation phase.
Invoke-LabChecked { python scripts/collect_assessments.py --subscription $sub --cluster-id $clusterId --phase $phase }
Invoke-LabChecked { python scripts/collect_arg.py --subscription $sub --cluster-id $clusterId --phase $phase }
```

## Validation

```text
python -m unittest discover -s tests -v
python -m unittest discover -s manifests/tests -v
az bicep build --file infra/main.bicep --outfile infra/main.json
```

October 7 local checks: 55 tests passed, and both Bicep templates compiled. The collectors and Kubernetes comparison also ran against the live lab. These results do not establish a Defender finding or clearance. See the dated verification record and public comparison for the measured scope.

## Time and costs

The two-node system pool uses Linux `Standard_D4as_v4`. Compute, disks, load balancing/public IP, Defender coverage and any telemetry are billable. Query prices for your chosen region and agreement. This run has an approved USD 50 allowance, with same-day cleanup scheduled for 00:15 UTC on October 8 (19:15 America/Chicago on October 7). This is an operating allowance, not an Azure-enforced billing cap or a measured invoice.

The Azure-hosted cleanup guard was deployed. A manual pre-deadline check read the owned group successfully and skipped deletion as expected. The completed run was cleaned up manually before expiry; the group, cluster, managed node group, and cleanup workflow are gone. A tag alone does not enforce expiry. Verify the cleanup workflow and its scope before leaving any reproduction unattended.

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
