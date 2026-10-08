# Defender for Cloud: controller-scoped KSPM evidence lab

Status on October 8, 2026 (UTC): two runs on AKS 1.35.8 in North Central US.

- **Run 1 (October 7)** completed the Kubernetes demonstration. Live comparisons in `results/` document pod replacement, scaling, a template change, and replacement after hardening. Its Defender checks returned nothing, but the workload existed for about 65 minutes, far short of Microsoft's documented wait of up to 24 hours for assessments, so that negative is uninformative. The cluster was deleted at about 21:37 UTC.
- **Run 2 (October 7 into October 8)** rebuilt the cluster under the same names with a differently named Deployment, `kspm-scope-proof-v2`, frozen at its two-replica baseline since 23:05:37 UTC. Through 00:27 UTC on October 8, no Defender assessment of any kind referenced the cluster, including control-plane recommendations. The cluster had not entered the assessment pipeline. See [`results/run2-defender-observation.json`](results/run2-defender-observation.json). Scheduled cleanup fires at 22:47:38 UTC on October 8 unless the deadline is deliberately extended.

**No live KSPM finding has been observed in either run.** The completed Kubernetes demonstration does not establish Defender finding identity, cardinality, stability, or clearance. The companion article carries an evidence-status note that says the same thing.

This package pairs a reproducible Kubernetes ownership experiment with collection tools for evaluating the October 5, 2026 change to workload-controller scope in Defender recommendations. Kubernetes behavior and Defender assessment behavior require separate evidence. Neither is an admission-control, image-CVE, or runtime-malware test.

## Question

When replaceable pods change, what happens to the recommendation's identity, target resource, cardinality and remediation status? Do consumers that deduplicate tickets or match exceptions by resource retain the intended scope?

The release announcement establishes the scope change. It does not establish the answers to those questions, and it does not promise that two replicas become one record.

## Which recommendation is under test

Microsoft previewed agentless, container-level KSPM misconfiguration recommendations in Defender CSPM on June 1, 2026, including one titled *Containers should use a read-only root filesystem*, and made them generally available on July 1, 2026. The October 5, 2026 entry moves those recommendations from the container instance to its Deployment or top-level controller. Microsoft's [container recommendation catalog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container), last updated July 1, still lists only the Azure Policy-backed title, *Immutable (read-only) root filesystem should be enforced for containers*.

In the lab subscription's assessment metadata (1,305 definitions), the June title does not exist. Two definitions carry the catalog title:

| Assessment key | Policy definition | Management | Dates | Reading |
|---|---|---|---|---|
| `b4262879-2a96-468f-bacd-6ed4d567bbdd` | none | MDC | public 2026-04-01, GA 2026-07-01 | The most plausible agentless definition; its GA date matches the container-level GA. Unproven until a record arrives. |
| `27d6f0e9-b4d5-468b-ae7e-03d5473fd864` | `df49d893-a74c-421d-bc95-c663042e5b80` | Azure Policy for Kubernetes | legacy | Requires the Azure Policy add-on, which this lab does not install. |

Attribute any future record by assessment key and policy definition, never by title alone. Microsoft's troubleshooting page says configuration-based recommendations will not trigger without the Azure Policy add-on; the June 1 note says the new recommendations need no runtime agent. Which statement governs the new check is exactly what the Defender track has to observe. Do not install the add-on to force a result; that would exercise the legacy path.

## Tested deployment

- Existing primary lab subscription and its existing Defender CSPM and Defender for Containers settings: agentless discovery for Kubernetes, registry vulnerability assessment, and container sensor auto-provisioning were already enabled. No plan was changed by this lab.
- Dedicated resource group `nls-kspm-scope-20261007` and cluster `nls-kspm-scope` in North Central US, deployed twice. East US rejected the first attempt due to regional AKS capacity; that failed attempt created no cluster.
- Free AKS control-plane tier; two `Standard_D4as_v4` nodes; Azure Linux; Kubernetes 1.35.8. This follows the current system-pool guidance (two nodes, at least four vCPUs per node).
- Entra authentication and Azure RBAC, local administrator accounts disabled; cluster-only administration for the current operator.
- API access restricted to the operator's explicitly supplied egress CIDR. Defender uses its documented Trusted Access path and needs no extra endpoint.
- No application Service or ingress. The namespace has restricted Pod Security admission and a default-deny NetworkPolicy.
- One Deployment with two replicas (run 1 later scaled to four), using the digest-pinned Kubernetes pause image. The only intentional security configuration weakness is a writable root filesystem. The test container does not run injected commands, use credentials, expose a port, or access host resources.
- No Azure Policy add-on, Helm sensor, Sentinel workspace, or new policy assignment. In run 2, Defender for Containers auto-provisioned its own sensor into `kube-system` at 23:30:01 UTC without operator action; each capture now records that state.

The selected SKU had available quota and no location restrictions in North Central US at deployment. Always query your own subscription's SKU restrictions, quotas and supported Kubernetes versions. Successful ARM validation does not guarantee regional control-plane capacity.

## What worked in the live test

All times below are **October 7, 2026 UTC**, shown to the second. Linked artifacts retain fractional-second timestamps and hashes of the underlying captures.

| Experiment | Before → after capture | Observed Kubernetes result |
|---|---|---|
| [Initial pod replacement](results/pod-replacement-comparison.json) | 20:33:02 → 20:55:54 | Two ready replicas; one original pod retained, one replaced. Same Deployment and active ReplicaSet. The replacement still had `readOnlyRootFilesystem: false`. |
| [Scale](results/scale-comparison.json) | 21:22:02 → 21:22:53 | Two → four ready replicas; two original pods retained, two new. Same Deployment and active ReplicaSet. All four matched the original writable-root template. |
| [Template change](results/template-remediation-comparison.json) | 21:22:53 → 21:23:52 | Four → four ready replicas; four replacement pods and a new active ReplicaSet. Same Deployment UID. The template and all four pods had `readOnlyRootFilesystem: true`. |
| [Replacement after hardening](results/hardened-replacement-comparison.json) | 21:23:52 → 21:24:43 | Four ready replicas; three original pods retained, one replaced. Same Deployment and active ReplicaSet. All four retained the read-only setting. |

The 21:22:02 capture is a new snapshot of the same two pods that existed at 20:55:54, not a new workload. The requested image and observed image-ID set were unchanged in all four comparisons. The results establish controller identity, ready pause containers, and propagation of the selected configuration. We did **not** execute an application write-denial test. The timestamps delimit snapshots, not measured rollout or replacement latency, and do not establish continuous state between observations.

The comparator verified the source hashes, ownership chain, readiness and scope before producing the public comparison. Raw identifiers and captures remain private. The comparison file contains no subscription ID, cluster endpoint, raw Kubernetes UID, or credential. The first comparison was produced before the comparator required a cluster resource UID, which is why it reports `clusterResourceUidCompared: false`; the current comparator refuses captures without one.

## What the Defender checks established so far

Both runs used the same read-only collectors against two surfaces: the paginated ARM assessment list and Azure Resource Graph. Resource Graph consistently returns eight identity assessments that the subscription-scope ARM list omits; the 133 shared records matched on identity and status, and no Kubernetes record was in either set.

| Run | Workload lifetime at last check | Checks | Matching candidates | Assessments referencing the cluster at all |
|---|---|---|---|---|
| 1 | about 54 minutes (deleted at about 65) | 8, from 20:36:45 to 21:26:08 UTC | 0 | 0 |
| 2 | 82 minutes, workload unchanged | 7, from 23:08:26 to 00:27:14 UTC | 0 | 0 |

Zero cluster references means Defender had not produced even the control-plane recommendations that need no workload discovery, such as the Defender-profile or diagnostic-logs checks. That is the single most useful observation from the Defender track so far: the absence of a KSPM record is uninformative until the cluster has been assessed at all. Microsoft documents that assessment scans can take up to 24 hours to appear and that agentless discovery changes can take up to 24 hours to reach the security graph. Neither is a KSPM SLA.

Run 2 also recorded, without interpreting them as a finding:

- The Defender security operator, its subscription role, and the Trusted Access binding `defender-cloudposture` with the `microsoft-defender-operator` role (in-cluster role binding created 23:04:42 UTC). This establishes access, not a completed discovery scan.
- Defender sensor components in `kube-system` from 23:30:01 UTC, and an empty `addonProfiles`; the policy-backed path was never provisioned.
- An Azure CSPM standard assigned to the subscription with the Audit effect, listing assessment key `b4262879`; no exempt or attest assignment at the subscription or its management-group ancestor; no legacy policy exemptions at subscription, resource-group or cluster scope. Native standard-assignment reads at resource-group and cluster scope failed and remain a gap.

An empty Defender result is an observation limit, not healthy status. If no record arrives within the time and budget, retain the completed Kubernetes comparisons and report the Defender experiment as unobserved, then change exactly one variable before any rerun.

## Two evidence tracks

The Kubernetes demonstration can finish even when Defender has not returned a finding. Choose the track before changing the workload:

| Capture phase | Kubernetes demonstration | Additional evidence for a Defender comparison |
|---|---|---|
| `baseline` | Two ready replicas with the original template | An actual matching KSPM assessment and its target fields |
| `scaled` | Scale to four; compare Pod UIDs and the active ReplicaSet | A refreshed assessment demonstrably representing the scaled workload |
| `remediated` | Patch the template to read-only; verify ready replacement pods | A subsequent service assessment; a Kubernetes setting is not Defender clearance |
| `rolled` | Replace one pod after hardening; verify the setting persists | A subsequent assessment before asserting finding identity or scope stability |

For the **Kubernetes track**, use the commands below and capture each ready state. For the **Defender track**, stop at baseline until a matching assessment exists, then wait for refreshed evidence between interventions. Do not perform rapid changes and retrospectively assign delayed service records to each phase. Run 1 made that mistake; run 2 corrects it.

What counts as the first Defender observation: an Unhealthy assessment under the resolved key whose assessed resource resolves to the lab namespace, the current Deployment name, and the current cluster instance; a second surface corroborating it with timestamps after the baseline; the raw capture hashed and kept private; a redacted public excerpt. A record naming pods instead of the controller is also publishable, as evidence that the tenant had not received the scope change.

## Reproduce the isolated environment

Requires Python 3.12+, Azure CLI, Bicep, native `kubectl`, `kubelogin`, and permissions to create an AKS cluster and its scoped role assignments. The PowerShell example requires PowerShell 7.5+ so date strings remain strings. Set your own public operator IPv4 /32. Confirm the applicable Defender plan and `AgentlessDiscoveryForKubernetes` are already enabled; this lab never enables a subscription-wide plan for you.

Choose `--hours` to cover the evidence you need. Microsoft's documented wait for a first assessment is up to 24 hours, and a stability or clearance comparison needs a second window after the change. The helper accepts 1 to 72 hours; budget the compute, disks, public IP, load balancer, Defender coverage and workflow runs for that window separately. The default of 4 hours only suits the Kubernetes track.

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
$prepared = (Invoke-LabChecked { python scripts/prepare_run.py --subscription $sub --operator-cidr $cidr --location northcentralus --hours 48 }) | ConvertFrom-Json
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

Extending a deadline later takes two writes that must agree: redeploy `infra/cleanup.bicep` with the new `expiresUtc`, and set the group's `expiresUtc` tag to the identical string. The workflow deletes only when the tag equals its compiled value, so editing the tag alone silently disables cleanup. Rerun the pre-deadline skip check afterwards.

If automatic discovery access has not appeared, first verify the existing `DefenderCSPMSecurityOperator` and its assigned role, then follow the [documented Trusted Access recovery procedure](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#what-do-i-do-if-i-have-locked-resource-groups-subscriptions-or-clusters). Bind only `Microsoft.Security/pricings/microsoft-defender-operator` to this lab cluster using the verified security-operator resource. Do not add the policy-writing or network-policy-writing roles for this posture experiment. The binding is not a scan-now command; no supported immediate reevaluation was found in Microsoft's documentation, the live `Microsoft.Security` provider operations, or the portal.

## Evidence collection

`scripts/collect_assessments.py` calls the documented read-only ARM assessment-list API. It captures all pages, rejects pagination URLs outside the exact subscription assessment collection, and records a SHA-256 digest. Raw subscription data is saved only under ignored, access-restricted `private/`.

```text
python scripts/collect_assessments.py --subscription <subscription-guid> --cluster-id <exact-cluster-resource-id> --phase baseline
```

`scripts/collect_arg.py` independently collects the same documented assessment resource type through Azure Resource Graph. It follows `$skipToken`, rejects unaccounted truncation, and scopes the request to the supplied subscription. It accepts the same arguments as the ARM collector. These are separate data surfaces; compare capture times before interpreting different total counts.

Both collectors now report two things beyond the broad candidate count: `resourceTypeCounts`, the assessed-resource types present in the capture, and `clusterReferencedAssessments`, the records whose assessed resource is the cluster or anything under it, for any recommendation. Check the second number first. While it is zero, the cluster has not been assessed at all and no KSPM conclusion is possible.

The candidate filter is deliberately broad. Its count is **not** the measured finding count. Manually confirm the recommendation type, cluster, namespace, workload and target fields before selecting the evidence set. Both collectors report schema paths from returned JSON but assume no new controller field or assessment ID. Read-only requests retry transient connection resets; writes are never automatically retried.

For each phase, the Kubernetes capture records the selected Deployment, its ReplicaSets and Pods with owner-reference UIDs, the namespace's NetworkPolicy and ResourceQuota objects, the UTC time, and the cluster's Defender component state (`clusterSecurityState`: Azure Policy add-on and Defender sensor profile flags). It does not record the applied manifest's hash; record `Get-FileHash` of each manifest you apply alongside the deployment receipt. Keep kubeconfig and unredacted JSON private. Do not interpret an empty assessment result as health or successful remediation.

Only derive a workload-owner ARG query after inspecting live assessment fields. Until then, `queries/discover-assessments.kql` is a schema-discovery query, not a finished controller resolver.

The Kubernetes collector exits 0 only for a complete ready snapshot; exit 2 preserves incomplete rollout evidence; exit 1 means identity or collection failure. It checks the selected API hostname against Azure, then validates controller owner references by UID. The comparison helper requires intact hash sidecars, complete ready captures, matching scope, a cluster resource UID present in both captures, and increasing UTC times. Its public output reports only selected observations and comparison counts, never a Defender verdict.

## Run the Kubernetes demonstration

Run from the repository root using the variables and checked-command function above. Use the dedicated kubeconfig created for this cluster, not the default context. The following creates only the four named fixtures; applying the entire directory would incorrectly treat a JSON Patch document as a Kubernetes resource.

Pick the Deployment fixture for this cluster instance. `baseline-deployment.json` names `kspm-scope-proof`; `baseline-deployment-v2.json` is identical except for the name `kspm-scope-proof-v2`. A new cluster instance under reused Azure names should use a Deployment name it has never used before, so a cached Defender record cannot be mistaken for fresh evidence. Pass that name to every capture with `--deployment`.

```powershell
$namespace = 'nls-kspm-controller-lab'
$deployment = 'kspm-scope-proof-v2'          # or 'kspm-scope-proof'
$fixture = 'baseline-deployment-v2.json'     # or 'baseline-deployment.json'
$existingNamespace = Invoke-LabChecked { kubectl --kubeconfig $kubeconfig get namespace $namespace --ignore-not-found --output name }
if ($existingNamespace) { throw 'The fixture namespace already exists; reconcile the previous run first.' }
foreach ($manifest in @('namespace.json', 'default-deny-networkpolicy.json', 'resource-quota.json', $fixture)) {
    Invoke-LabChecked { kubectl --kubeconfig $kubeconfig apply --filename "manifests/$manifest" }
}
Invoke-LabChecked { kubectl --kubeconfig $kubeconfig --namespace $namespace rollout status "deployment/$deployment" --timeout=300s }

function Save-LabSnapshot {
    param([ValidateSet('baseline','scaled','remediated','rolled')][string]$Phase)
    $receipt = (Invoke-LabChecked { python scripts/capture_kubernetes.py --subscription $sub --cluster-id $clusterId --experiment-id $experiment --kubeconfig $kubeconfig --deployment $deployment --phase $Phase }) | ConvertFrom-Json
    Join-Path 'private' $receipt.file
}
$baseline = Save-LabSnapshot baseline
$runStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
New-Item -ItemType Directory -Path 'results' -Force | Out-Null

# Defender track: stop here and collect on a schedule until a matching record exists.
# Kubernetes track: continue.

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

The RFC 6902 patch first tests that container zero is named `pause`, then sets only its `readOnlyRootFilesystem` field to `true`. Here, `remediated` is a phase label for a Kubernetes configuration change, not a Defender verdict; see the recommendation-identity section above for what the service would have to return.

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

Run this isolated experiment without another operator changing its objects; the read-before-delete check is not an atomic UID precondition on deletion. If a capture exits 2, allow the workload to settle and repeat **only that capture**, then its comparison. Do not reapply the baseline manifest to "fix" a capture: that would reset replicas and the security setting. The comparison must show what was observed; no unchanged UID, replacement, or image invariant is assumed from the phase name.

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
az bicep build --file infra/cleanup.bicep --outfile infra/cleanup.json
```

October 8 local checks: 69 tests passed (17 collector, 10 Resource Graph, 16 Kubernetes capture, 9 comparison, 8 manifest, 7 cleanup, 2 parameter), and both Bicep templates compiled. The collectors, the Kubernetes capture and the comparison also ran against the live lab. These results do not establish a Defender finding or clearance. See [`results/verification-status.json`](results/verification-status.json) for the dated record of both runs.

## Time and costs

The two-node system pool uses Linux `Standard_D4as_v4`. Compute, disks, load balancing/public IP, Defender coverage and any telemetry are billable. Query prices for your chosen region and agreement. Both runs share one cumulative operating allowance of USD 50; this is a planning allowance, not an Azure-enforced billing cap or a measured invoice. Run 1 ran for about 65 minutes before manual cleanup. Run 2's cleanup workflow is scheduled for 22:47:38 UTC on October 8, 2026, about 23.7 hours after its baseline.

The Azure-hosted cleanup guard was deployed in both runs. In each, a manual pre-deadline run read the owned group and evaluated its condition as two separate results: ownership matched, deadline not reached, so deletion was skipped. Run 1 was then cleaned up manually before expiry; its group, cluster, managed node group and cleanup workflow were verified absent. Run 2's group exists until its deadline or an explicit extension. A tag alone does not enforce expiry. Verify the cleanup workflow and its scope before leaving any reproduction unattended.

Cleanup must bind the exact subscription, resource-group ID and experiment tag to the deployment receipt. Refuse an existing or mismatched group. Delete only this experiment's group, then verify both it and the AKS-managed node group are gone. Preserve existing subscription security plans and all other lab resources.

`scripts/prepare_run.py` prepares private ARM parameters from the signed-in operator and a public IPv4 /32. It creates no resources. `scripts/cleanup_lab.py` defaults to read-only planning and requires a deployment receipt plus its separately retained SHA-256 digest. It checks live identities, tags, the managed-node-group relationship, and unexpected resources. `--execute` requests deletion; a later read must confirm completion. Neither helper schedules cleanup by itself.

Receipt fields: `subscriptionId`, `resourceGroupId`, `clusterId`, `experimentId`, `nodeResourceGroupId`, and optional `clusterResourceUid` if returned by Azure. Create one receipt per cluster instance from successful live deployment outputs and record its digest in the authorized monitoring configuration. Never synthesize a receipt from guessed resource identities, and never reuse a receipt across instances that share names.

## Sources

- [October 5 scope-change announcement](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#kspm-misconfiguration-recommendations-moving-to-controller-level-scope-ga)
- [June 1 preview of container-level recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#container-level-misconfiguration-recommendations-for-kubernetes-preview) and [July 1 general availability](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#new-container-security-capabilities-are-now-generally-available)
- [Recommendation release notes with the June 1 title list](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-recommendations-alerts)
- [Container recommendation catalog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container)
- [Defender for Containers troubleshooting (assessment wait, policy add-on)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-troubleshoot)
- [Discovery support matrix](https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-containers#security-posture-management-features)
- [Network access and Trusted Access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-network-access#azure-kubernetes-service-aks)
- [Discovery refresh FAQ](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#whats-the-refresh-interval-for-agentless-discovery-of-kubernetes)
- [Assessment-list API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-stable)
- [Assessment metadata API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments-metadata?view=rest-defenderforcloud-composite-stable)
- [Individual assessment model](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Azure retail pricing API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
- [AKS system-pool restrictions](https://learn.microsoft.com/en-us/azure/aks/use-system-pools#system-and-user-node-pools)
