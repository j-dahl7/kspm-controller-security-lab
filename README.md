# Defender for Cloud: controller-scoped KSPM evidence lab

Status as of October 9, 2026 at 17:49 UTC: two runs on AKS 1.35.8 in North Central US. The product result is observed; the article and evidence package are awaiting review and publication approval.

- **Run 1 (October 7)** completed the Kubernetes demonstration. Live comparisons in `results/` document pod replacement, scaling, a template change, and replacement after hardening. No matching Defender finding was observed before the workload was changed and removed. Its roughly 65-minute lifetime did not establish a Defender baseline. Both resource groups were verified absent at about 21:37 UTC.
- **Run 2 (October 7–9)** established two agentless findings before changing the workload. After the owning Deployment template was hardened, the trusted-registry finding named a verified post-rollout pod while preserving its exact assessment and assessed-resource identities. The read-only-root-filesystem finding disappeared from complete ARM and Resource Graph exports, returned 404 at its former address, and was no longer listed in the portal. No explicit Healthy or resolved root-filesystem record was returned. The isolated single-pod service test was inconclusive; no run-2 scaling or post-hardening replacement test was performed.

**The observed result is removal of the root-filesystem finding, with fresh controller-attributed registry evidence.** The [October 9 result](results/run2-post-rollout-evidence.json) distinguishes that from an explicit Healthy transition. The [October 8 baseline/intervention record](results/run2-product-evidence.json) is historical; its pod names are now explicitly documented aliases in the shareable derivative, with original source hashes preserved.

The original unfinished post and lab page were withdrawn. Their replacements remain unpublished drafts. Lab pushing and site publishing still require approval. The user authorized run-2 teardown on October 12; both the experiment resource group and its AKS-managed node group were verified absent at 14:49:51 UTC. Automatic checks remain paused. The cumulative allowance was USD 50, a planning allowance rather than an Azure-enforced billing cap.

This package pairs a reproducible Kubernetes ownership experiment with collection tools for evaluating the October 5, 2026 change to workload-controller scope in Defender recommendations. Kubernetes behavior and Defender assessment behavior require separate evidence. Neither is an admission-control, image-CVE, or runtime-malware test.

## Question

When replaceable pods change, what happens to the recommendation's identity, target resource, cardinality and remediation status? Do consumers that deduplicate tickets or match exceptions by resource retain the intended scope?

The release announcement establishes the scope change. This lab observed a stable registry finding identity across the template rollout and removal of the root-filesystem finding afterward. It does not establish a universal identity guarantee or promise that two replicas become one record.

## Which recommendation is under test

Microsoft previewed agentless, container-level KSPM misconfiguration recommendations in Defender CSPM on June 1, 2026, including one titled *Containers should use a read-only root filesystem*, and made them generally available on July 1, 2026. The October 5 entry starts from individual container-instance scope and moves recommendations to a Deployment or top-level controller, but does not explicitly name the June checks or map their identifiers. We read it as the next scope change in that lineage; the October 8 captures now establish the fields returned for this lab. Microsoft's [container recommendation catalog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container), last updated July 1, still lists the Azure Policy-backed title, *Immutable (read-only) root filesystem should be enforced for containers*.

In the lab subscription's assessment metadata (1,305 definitions), the June title does not exist. Two definitions carry the catalog title:

| Assessment key | Policy definition | Management | Dates | Reading |
|---|---|---|---|---|
| `b4262879-2a96-468f-bacd-6ed4d567bbdd` | none | MDC, observed on detail GET | public 2026-04-01, GA 2026-07-01 | Observed KSPM-Agentless finding with explicit Deployment attribution on October 8. Historical release mapping remains an interpretation; the April public date predates June. |
| `27d6f0e9-b4d5-468b-ae7e-03d5473fd864` | `df49d893-a74c-421d-bc95-c663042e5b80` | Azure Policy for Kubernetes | legacy | Requires the Azure Policy add-on, which this lab does not install. |

Correlate a record's actual recommendation fields with its metadata and policy definition; do not assume the record's `name` equals the metadata key or use its title alone. The detail GET using API version `2021-06-01` returned `managementProvider: MDC` and `cloudProviders: [Azure]`; the bulk metadata list omitted those fields. That observed response is not a guarantee that every API surface exposes them.

Microsoft's troubleshooting page says configuration-based recommendations will not trigger without the Azure Policy add-on, and the support matrix's workload-hardening row requires Azure Policy. The June release describes the new checks as agentless; the [architecture table](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-architecture#capability-model-overview) also marks Kubernetes posture assessment as requiring no in-cluster component. In this lab, AKS configuration did not enumerate an Azure Policy add-on, and Defender's own add-on recommendation (`08e628db-e2ed-4793-bc91-d13e684401c3`) was Unhealthy while both `KSPM-Agentless` findings were present. Those two agentless checks therefore produced findings without the add-on here. This observation does not remove Azure Policy prerequisites from every workload-hardening check.

## Tested deployment

- Existing primary lab subscription and its existing Defender CSPM and Defender for Containers settings: agentless discovery for Kubernetes, registry vulnerability assessment, and container sensor auto-provisioning were already enabled. No plan was changed by this lab.
- Dedicated resource group `nls-kspm-scope-20261007` and cluster `nls-kspm-scope` in North Central US, deployed twice. East US rejected the first attempt due to regional AKS capacity; that failed attempt created no cluster.
- Free AKS control-plane tier; two `Standard_D4as_v4` nodes; Azure Linux; Kubernetes 1.35.8. This follows the current system-pool guidance (two nodes, at least four vCPUs per node).
- Entra authentication and Azure RBAC, local administrator accounts disabled; cluster-only administration for the current operator.
- API access restricted to the operator's explicitly supplied egress CIDR. Defender uses its documented Trusted Access path and needs no extra endpoint.
- No application Service or ingress. The namespace has restricted Pod Security admission and a default-deny NetworkPolicy.
- One Deployment with two replicas (run 1 later scaled to four), using the digest-pinned Kubernetes pause image. The only intentional security configuration weakness is a writable root filesystem. The test container does not run injected commands, use credentials, expose a port, or access host resources.
- No Azure Policy add-on, Helm sensor, Sentinel workspace, or new policy assignment. In run 2, separately inspected sensor pods showed that Defender for Containers auto-provisioned its own sensor into `kube-system` at 23:30:01 UTC without operator action. The Kubernetes capture helper records ARM configuration flags, not sensor-pod state or health.

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

## What the Defender observations established

The historical [`October 8 product evidence`](results/run2-product-evidence.json) preserves allowlisted fields from eight complete, hash-verified exports: the 13:20 UTC baseline, 14:02 UTC post-replacement check, 14:20 UTC pre-template check, and 14:23 UTC post-template check, each on ARM and Resource Graph. ARM returned 145 assessments and ARG 153 at each observation. Both returned the same two KSPM records for this workload; the extra eight ARG records are IAM identities. Candidate counts include unrelated infrastructure checks and are not workload finding counts.

| Recommendation | Key | Status | Metadata severity | Contextual risk |
|---|---|---|---|---|
| Immutable (read-only) root filesystem should be enforced for containers | `b4262879-2a96-468f-bacd-6ed4d567bbdd` | Unhealthy | Medium | Low |
| Container images should be deployed from trusted registries only | `12ceffa0-bd66-4ae9-abbf-58f88b0a7bc0` | Unhealthy | High | Low |

The writable root filesystem was the intended weakness, but Defender also flagged the fixture's registry. Metadata severity and the portal's contextual **Risk level** are different fields; a Low risk row does not make the trusted-registry recommendation's metadata severity Low.

Each recommendation returned one record for the two ready replicas. That is the count in this fixture, not a general conversion rule. Both retain `ResourceType: k8s-container`, with `additionalData.source: KSPM-Agentless`, `topLevelKind: Deployment`, and `topLevelName: kspm-scope-proof-v2`. The assessed identity tail is:

```text
namespace-nls-kspm-controller-lab-toplevelworkloadkind-deployment-pod-kspm-scope-proof-v2-container-pause
```

The segment labeled `pod-` holds the **Deployment name**, not a pod name. The actual supporting pod name lives in `additionalData.podName`. Use the returned fields and verified ownership chain; string labels alone can mislead a downstream join.

Defender's service timestamps put five cluster-level checks at 05:32:27 UTC and the two KSPM checks at 05:37:44 UTC. The workload's first pods were created at 23:05:16 UTC the previous evening, about 6.5 hours earlier. We first retrieved a matching export at 13:20 UTC. There is a successful-capture gap from about 02:09 to 13:20 UTC, so these timestamps do not measure delivery latency or establish a fixed scan interval. Run 1's roughly 65-minute workload lifetime is consistent with this timing; it does not establish why that run returned no finding.

At 13:41 UTC, the pod named by Defender was replaced once. The before/after snapshots show one retained pod, one new pod, the same Deployment and active ReplicaSet, an unchanged writable-root template and image, and two ready replicas. Through the 14:20 UTC pre-template check, the service still returned the deleted pod name and unchanged dates for both checks. The assessment and target IDs repeated, but a repeated old record does not prove identity stability through reassessment. The standalone replacement stage closed inconclusive when the user chose to prioritize the template fix; later observations cannot retrospectively prove that stage.

The root-filesystem recommendation's remediation text says, "For these pods, set the readOnlyRootFilesystem flag to 'true'" and "redeploy the pod with the updated spec." Here the returned target identifies the Deployment, so the intended fix is the owning template. The later result below comes from Defender observations; Kubernetes configuration alone would not establish it.

At 14:22:34 UTC, the authorized patch changed only the container template's `readOnlyRootFilesystem` field from false to true, using identity, generation, resource-version and prior-value tests. There was no scale step: the target remained two replicas. The [14:23:42 UTC Kubernetes comparison](results/run2-template-remediation-comparison.json) confirms the same Deployment, a new active ReplicaSet, two new ready pods with read-only roots, and unchanged image and image-ID values. This checks configuration and readiness, not an application write-denial test.

At 14:23:47 UTC on October 8, both service records were still Unhealthy, with the old supporting pod and unchanged dates. That historical response did not establish a fresh evaluation of the hardened workload. The trusted-registry finding was retained as a control because the image and registry configuration did not change.

By the October 9 checks, the results were different:

| Observation | Evidence | What it establishes |
|---|---|---|
| Registry finding remained Unhealthy and named a pod created by the template rollout | Complete ARM and Resource Graph exports, exact virtual-address GET, and Kubernetes UID reconciliation | Fresh supporting data for this rollout; the exact assessment ID and assessed-resource details match the baseline and pre-patch records. |
| Root-filesystem finding was no longer returned | Zero matches in complete ARM (171 records) and ARG (179 records); HTTP 404 at its previously observed virtual address; no row in the portal with the status filter removed | Observed finding removal. No explicit Healthy or resolved payload was returned. |
| Registry first-evaluation and status-change dates stayed at October 8 05:37:44 UTC | Both old and new payloads | Those dates are not last-scan timestamps; they did not advance when the supporting pod changed. |

The last complete capture containing the root-filesystem finding was October 9 at **14:21:28 UTC**. The first complete capture without it was **17:43:11 UTC**. That interval bounds what we observed; it is not an exact removal time, a measured assessment latency, or an SLA. The recommendation's global metadata still returned HTTP 200. Definition availability does not by itself rule out exemptions or reveal the service's internal removal reason.

The control's fresh pod reference shows that Defender processed post-rollout workload data, and the separate root-filesystem observations show that its finding was removed. This supports the reported result for this experiment. It does not convert the absent root-filesystem record into a Healthy status or retrospectively complete the earlier single-pod test. The [post-rollout evidence](results/run2-post-rollout-evidence.json) contains the before/after fields, identity comparisons, source hashes and claim limits.


Prerequisite and assignment observations remain context: Trusted Access was manually configured, Defender sensor components appeared at 23:30 UTC, and the Azure CSPM standard was assigned with Audit. No native Exempt/Attest was returned at the subscription or observed ancestor; child-scope native reads remain a documented gap. These configuration facts did not themselves prove discovery. The actual KSPM records do.

The [independent fact audit](results/review-addendum-facts.json) records 32 complete ARG exports across both runs: two preflights, six run-1 post-workload exports and 24 run-2 post-baseline exports. They contain 33 repeated row sightings of two KSPM-Agentless findings, all Unhealthy in this sample. That is not 33 distinct findings or a guarantee that Healthy can never appear. These ARG-only counts are separate from the run-2 combined ARM/ARG export index.

The same audit verifies that an ARM response still named the deleted pod about 24 hours 40 minutes after its deletion request was accepted; the preceding ARG observation was about 24 hours 34 minutes after that request. The old ReplicaSet remained with its original writable-root template, zero desired/actual replicas and no current owned pods, while the active workload was read-only and the root-filesystem finding was absent. This documents this run's inactive revision history, not a general evaluator rule.

The full dated export index is in [`results/run2-defender-observation.json`](results/run2-defender-observation.json). Empty early checks remain historical observations, not Healthy results or proof of absent backend processing. Microsoft's timing guidance is not an SLA and does not establish mandatory serial 24-hour stages.

## Two evidence tracks

The Kubernetes demonstration can finish even when Defender has not returned a finding. Choose the track before changing the workload:

| Capture phase | Kubernetes demonstration | Additional evidence for a Defender comparison |
|---|---|---|
| `baseline` | Two ready replicas with the original template | An actual matching KSPM assessment and its target fields |
| `scaled` | Scale to four; compare Pod UIDs and the active ReplicaSet | A refreshed assessment demonstrably representing the scaled workload |
| `remediated` | Patch the template to read-only; verify ready replacement pods | A subsequent service assessment; a Kubernetes setting is not Defender clearance |
| `rolled` | Replace one pod after hardening; verify the setting persists | A subsequent assessment before asserting finding identity or scope stability |

For the **Kubernetes track**, use the commands below and capture each ready state. For the **Defender track**, stop at baseline until a matching assessment exists, then wait for refreshed evidence between interventions. Do not retrospectively assign delayed service records to each phase. Run 1 changed too early. Run 2 established its baseline, but the user then chose to close the unrefreshed single-pod test as inconclusive and prioritize template remediation without scaling. The table is a general experiment plan; it does not claim every stage was completed in run 2.

The discovery milestone is an observed entity for the actual v2 workload, not just the reused cluster name or the manually created binding. An assessment may appear on a different surface before the graph snapshot refreshes; do not discard a valid controller assessment merely because the graph or explicit cluster-ID counter has not caught up.

What counts as the first Defender product observation: a genuine assessment correlated with verified recommendation metadata, whose observed target fields resolve to the lab namespace, current workload, and current cluster instance; a second view corroborating it; privately retained, hashed captures with service and collection timestamps distinguished. Record the exact identifier paths rather than assuming the finding name is the recommendation key. A pod-scoped record establishes the scope observed for that recommendation and resource at that time, not tenant-wide rollout status. Capture and review it without converting it into a controller-scope claim.

## Reproduce the isolated environment

Requires Python 3.12+, Azure CLI, Bicep, native `kubectl`, `kubelogin`, and permissions to create an AKS cluster and its scoped role assignments. The PowerShell example requires PowerShell 7.5+ so date strings remain strings. Set your own public operator IPv4 /32. Confirm the applicable Defender plan and `AgentlessDiscoveryForKubernetes` are already enabled; this lab never enables a subscription-wide plan for you.

Choose an explicitly authorized time and spending limit for a new run. Microsoft gives up-to-24-hour visibility guidance, not a guaranteed arrival time or a demonstrated minimum of 48 hours. Stability and clearance claims need later service observations after each intervention. The helper accepts 1 to 72 hours for a new run. Run 2 is complete and was cleaned up with the user's approval on October 12. Its cancelled October 8 deadline is historical; the cleanup workflow was removed with the experiment group. Budget compute, disks, public IP, load balancer, Defender coverage and workflow runs separately. A short window may finish without product evidence.

**The setup commands below are for a new, separately authorized environment. The completed run-2 environment has been deleted; these commands do not restore its original resource identity.**

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
$approvedHours = 24 # Example for a separately authorized NEW run; not a run-2 extension.
$prepared = (Invoke-LabChecked { python scripts/prepare_run.py --subscription $sub --operator-cidr $cidr --location northcentralus --hours $approvedHours }) | ConvertFrom-Json
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

For future timed runs only, and after explicit approval, extending a deadline takes two writes that must agree: redeploy `infra/cleanup.bicep` with the new `expiresUtc`, then merge the group's `expiresUtc` tag to the identical string. Use `az tag update --resource-id <group-id> --operation Merge --tags expiresUtc=<approved-UTC-value>` or `az group update --set tags.expiresUtc=<approved-UTC-value>`; replacing all tags would remove the ownership tags and disarm the guard. Read back the group tag, trigger `startTime`, and deadline literal in the deployed expression and confirm all three agree. A skipped pre-deadline run cannot prove those values match. If either write fails, reconcile the deployed guard and tags immediately rather than assuming either deadline remains armed.

If automatic discovery access has not appeared, first verify the existing `DefenderCSPMSecurityOperator` and its assigned role, then follow the [documented Trusted Access recovery procedure](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#what-do-i-do-if-i-have-locked-resource-groups--subscriptions--or-clusters-). Bind only `Microsoft.Security/pricings/microsoft-defender-operator` to this lab cluster using the verified security-operator resource. Do not add the policy-writing or network-policy-writing roles for this posture experiment. The binding is not a scan-now command; no supported immediate reevaluation was found in Microsoft's documentation, the live `Microsoft.Security` provider operations, or the portal.

## Evidence collection

`scripts/collect_assessments.py` calls the documented read-only ARM assessment-list API. It captures all pages, rejects pagination URLs outside the exact subscription assessment collection, and records a SHA-256 digest. Captured JSON stays in ignored, access-restricted `private/`. Known credential fields and signed access URLs are removed before writing; `credentialRedactions` identifies any affected fields.

```text
python scripts/collect_assessments.py --subscription <subscription-guid> --cluster-id <exact-cluster-resource-id> --phase baseline
```

`scripts/collect_arg.py` independently collects the same documented assessment resource type through Azure Resource Graph. It follows `$skipToken`, rejects unaccounted truncation, and scopes the request to the supplied subscription. It accepts the same arguments as the ARM collector. These are separate data surfaces; compare capture times before interpreting different total counts.

Both collectors report `resourceTypeCounts` and `clusterReferencedAssessments`. The latter counts selected explicit assessed-resource IDs matching the cluster or a path below it. Zero does not prove that the service never processed the cluster, and does not exclude a finding on a virtual Kubernetes entity. Neither summary is an acceptance gate by itself.

The candidate filter keeps independent leads: cluster/namespace/workload text, the candidate recommendation IDs wherever observed, either published root-filesystem title, and Kubernetes resource types. `candidateMatches` records why a record was selected. All assessment records remain in the capture. Supply `--workload` for the current Deployment and repeat `--assessment-key` to add candidate keys alongside the two defaults. Its count is **not** a measured finding count; verify the actual recommendation and target before accepting anything. A source of `Azure` alone is not a useful candidate filter. Read-only requests retry recognized transient transport failures and selected HTTP failures within five attempts. Authentication, scope and certificate-validation failures stop without retry. Writes are never automatically retried. A failed later ARM page saves a separately named incomplete capture with safe error category and attempt count; it is never reported as an empty complete export.

`scripts/probe_assessments.py` adds GETs for the two known cluster-scoped assessment addresses and their global metadata definitions. A 404 establishes only that the requested address was not found. It does not enumerate virtual-controller addresses or prove feature absence. Authorization, transport and other failures remain errors, not empty results.

`scripts/record_prerequisites.py` records the selected AKS configuration, plan extensions, and Trusted Access configuration. It verifies the selected scope and experiment tags, but does not establish effective coverage, running sensor health, completed discovery, or an assessment.

For each phase, the Kubernetes capture records the selected Deployment, its ReplicaSets and Pods with owner-reference UIDs, the namespace's NetworkPolicy and ResourceQuota objects, UTC time, and cluster configuration flags (`clusterSecurityState`). Those flags do not verify sensor operation. It does not record the applied manifest's hash or all namespace labels; preserve those separately when needed. Keep kubeconfig and private identifiers out of shared reports, and do not retain credentials in captures. Do not interpret an empty assessment result as health or successful remediation.

Only derive a workload-owner ARG query after inspecting live assessment fields. Until then, `queries/discover-assessments.kql` is a schema-discovery query, not a finished controller resolver.

The Kubernetes collector exits 0 only for a complete ready snapshot and exits 1 for identity or collection failure. Exit 2 can mean either a saved incomplete snapshot or an argument error; use the emitted JSON receipt and saved capture to distinguish them, not the exit code alone. An argument error produces no capture receipt and requires correcting the invocation. The helper checks the selected API hostname against Azure, then validates controller owner references by UID. The comparison helper requires intact hash sidecars, complete ready captures, matching scope, a cluster resource UID present in both captures, and increasing UTC times. Its public output reports only selected observations and comparison counts, never a Defender verdict.

## Run the Kubernetes demonstration

Run from the repository root using the variables and checked-command function above. Use the dedicated kubeconfig created for this cluster, not the default context. The following creates only the four named fixtures; applying the entire directory would incorrectly treat a JSON Patch document as a Kubernetes resource.

Pick the Deployment fixture for this cluster instance. `baseline-deployment.json` names `kspm-scope-proof`; `baseline-deployment-v2.json` changes the name, labels and matching selector to `kspm-scope-proof-v2`, keeping the workload configuration the same. A new cluster instance under reused Azure names should use a new Deployment name to distinguish workload-level records. Cluster-level records still share the reused Azure resource ID and require timestamps and identifiers reconciled with the current cluster instance. Pass the Deployment name to every capture with `--deployment`.

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

Run this isolated experiment without another operator changing its objects; the read-before-delete check is not an atomic UID precondition on deletion. If a capture exits 2 and its receipt confirms that an incomplete snapshot was saved, allow the workload to settle and repeat **only that capture**, then its comparison. If it instead reports an argument error, correct the invocation before retrying. Do not reapply the baseline manifest to "fix" a capture: that would reset replicas and the security setting. The comparison must show what was observed; no unchanged UID, replacement, or image invariant is assumed from the phase name.

For the separate Defender track, run both read-only collectors at each chosen phase, with no intervening workload changes while waiting for the corresponding service evidence:

```powershell
$phase = 'baseline' # Use the actual observation phase.
Invoke-LabChecked { python scripts/collect_assessments.py --subscription $sub --cluster-id $clusterId --workload $deployment --phase $phase }
Invoke-LabChecked { python scripts/collect_arg.py --subscription $sub --cluster-id $clusterId --workload $deployment --phase $phase }
Invoke-LabChecked { python scripts/probe_assessments.py --subscription $sub --cluster-id $clusterId --phase $phase }
Invoke-LabChecked { python scripts/record_prerequisites.py --subscription $sub --cluster-id $clusterId --experiment-id $experiment --phase $phase }
```

## Validation

```text
python -m unittest discover -s tests -v
python -m unittest discover -s manifests/tests -v
az bicep build --file infra/main.bicep --outfile infra/main.json
az bicep build --file infra/cleanup.bicep --outfile infra/cleanup.json
```

Local review checks: 99 tests passed, and both Bicep templates compiled. The collectors, Kubernetes capture and comparison also ran against the live lab. Software checks do not establish a Defender verdict; the separate product evidence establishes controller attribution, registry identity preservation, and observed root-filesystem finding removal. No explicit Healthy or resolved transition is claimed. See [`results/verification-status.json`](results/verification-status.json) for the dated record of both runs.

## Time and costs

The two-node system pool used Linux `Standard_D4as_v4`. Compute, disks, load balancing/public IP, Defender coverage and any telemetry are billable. Query prices for your chosen region and agreement. Both runs shared one cumulative operating allowance of USD 50; this was a planning allowance, not an Azure-enforced billing cap or a measured invoice. Run 1's workload existed for about 65 minutes before manual cleanup; that is not the cluster's billed lifetime. Run 2's former October 8 timer was cancelled at the user's direction. Its workflow was removed during the authorized October 12 teardown, and the old expiry in historical receipts remains historical.

The Azure-hosted cleanup guard was deployed in both runs. In each, a manual pre-deadline run read the owned group, evaluated the combined ownership-and-deadline condition as false, and skipped deletion. That is the expected result before the deadline; the run history alone does not identify which clause was false. Run 1 was cleaned up manually, and both groups were verified absent.

**Run 2 cleanup was verified on October 12 at 14:49:51 UTC.** After the user authorized teardown, the ownership-checked helper requested deletion of the experiment resource group at 14:32:37 UTC. Its successful deletion did not remove the AKS-managed node group. A separate review verified that remainder's parent relationship, ownership tags, unchanged six-resource inventory and lack of locks. A separately guarded operator helper requested deletion of that exact managed group at 14:46:22 UTC. Successful existence reads then confirmed both groups absent in the same verification round. This was a two-step manual cleanup, not automatic AKS removal of the managed group.

The pre-cleanup October 12 check found the subscription Disabled and the cluster Deallocated/Failed. Its dated operational snapshot is preserved in [`results/verification-status.json`](results/verification-status.json), alongside the later `cleanupOutcome` and the private verification capture's SHA-256. No subscription reactivation, spending-limit removal, billing change, or modification of shared Defender settings or other lab resources was performed. No final invoice or credit balance was measured.

The saved October 8-9 captures and screenshot inventory were preserved before teardown. They remain the basis for the product results. A new live Kubernetes capture was unavailable with the control plane deallocated; the cluster was not restarted. Resource deletion on October 12 is separate from the observed recommendation disappearance on October 9 and adds no new Defender assessment result. Automatic checks remain paused.

Cleanup must bind the exact subscription, resource-group ID and experiment tag to the deployment receipt. Refuse an existing or mismatched group. Delete only this experiment's group, then verify both it and the AKS-managed node group are gone. For a future timed run, or after an explicitly authorized deletion, check both groups again at approximately 15 and 75 minutes; an accepted asynchronous deletion request is not proof of completion. If the experiment group remains, inspect its state and use the ownership-checked cleanup helper as the fallback, then verify again. If only the managed node group remains, the helper refuses deletion and requires separate ownership review; it never directly deletes the managed group. Preserve existing subscription security plans and all other lab resources.

`scripts/prepare_run.py` prepares private ARM parameters from the signed-in operator and a public IPv4 /32. It creates no resources. `scripts/cleanup_lab.py` defaults to read-only planning and requires a deployment receipt plus its separately retained SHA-256 digest. It checks live identities, tags, the managed-node-group relationship, and unexpected resources. `--execute` requests deletion; a later read must confirm completion. Neither helper schedules cleanup by itself.

Receipt fields: `subscriptionId`, `resourceGroupId`, `clusterId`, `experimentId`, `nodeResourceGroupId`, `cleanupWorkflowId` for the deployed cleanup workflow, and optional `clusterResourceUid` if returned by Azure. Create one receipt per cluster instance from successful live deployment outputs and record its digest in the authorized monitoring configuration. Never synthesize a receipt from guessed resource identities, and never reuse a receipt across instances that share names.

## Sources

- [October 5 scope-change announcement](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#kspm-misconfiguration-recommendations-moving-to-controller-level-scope-ga)
- [June 1 preview of container-level recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#container-level-misconfiguration-recommendations-for-kubernetes-preview) and [July 1 general availability](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes#new-container-security-capabilities-are-now-generally-available)
- [Recommendation release notes with the June 1 title list](https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-recommendations-alerts)
- [Container recommendation catalog](https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-container)
- [Defender for Containers troubleshooting (assessment wait, policy add-on)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-troubleshoot)
- [Discovery support matrix](https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-containers#security-posture-management-features)
- [Network access and Trusted Access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-network-access#azure-kubernetes-service-aks)
- [Discovery refresh FAQ](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-containers#what-s-the-refresh-interval-for-agentless-discovery-of-kubernetes-)
- [Assessment-list API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-stable)
- [Assessment metadata API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments-metadata?view=rest-defenderforcloud-composite-stable)
- [Individual assessment model](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Azure retail pricing API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
- [AKS system-pool restrictions](https://learn.microsoft.com/en-us/azure/aks/use-system-pools#system-and-user-node-pools)
