"""Validate the isolated lab fixtures without Kubernetes or cloud access.

The hardening file is RFC 6902 JSON Patch, for kubectl patch --type=json.
These checks validate declared intent; they do not establish cluster admission,
network-policy enforcement, image availability, or Defender findings.
"""

import copy
import json
from pathlib import Path
import unittest


FIXTURES = Path(__file__).resolve().parents[1]
NAMESPACE = "nls-kspm-controller-lab"
READONLY_PATH = (
    "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem"
)


def read_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def changed_paths(before, after, path=""):
    """Return JSON-pointer paths changed by a proposed fixture mutation."""
    if type(before) is not type(after):
        return {path}
    if isinstance(before, dict):
        changes = set()
        for key in before.keys() | after.keys():
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before or key not in after:
                changes.add(child)
            else:
                changes.update(changed_paths(before[key], after[key], child))
        return changes
    if isinstance(before, list):
        if len(before) != len(after):
            return {path}
        changes = set()
        for index, (old, new) in enumerate(zip(before, after)):
            changes.update(changed_paths(old, new, path + "/" + str(index)))
        return changes
    return set() if before == after else {path}


def apply_hardening_patch(document, patch):
    """Apply only the two deliberately allowed JSON Patch operations locally."""
    result = copy.deepcopy(document)
    for operation in patch:
        tokens = operation["path"].lstrip("/").split("/")
        cursor = result
        for token in tokens[:-1]:
            token = token.replace("~1", "/").replace("~0", "~")
            cursor = cursor[int(token)] if isinstance(cursor, list) else cursor[token]
        key = tokens[-1].replace("~1", "/").replace("~0", "~")
        key = int(key) if isinstance(cursor, list) else key
        if operation["op"] == "test":
            if cursor[key] != operation["value"]:
                raise ValueError("Hardening patch selected an unexpected container")
        elif operation["op"] == "replace" and operation["path"] == READONLY_PATH:
            if key not in cursor:
                raise ValueError("Replace requires an existing security field")
            cursor[key] = operation["value"]
        else:
            raise ValueError("Unapproved hardening operation")
    return result


class ManifestSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deployment = read_fixture("baseline-deployment.json")
        cls.namespace = read_fixture("namespace.json")
        cls.network = read_fixture("default-deny-networkpolicy.json")
        cls.quota = read_fixture("resource-quota.json")
        cls.patch = read_fixture("harden-readonly.patch.json")

    def test_only_expected_resource_types_are_present(self):
        expected = {
            "namespace.json": ("v1", "Namespace"),
            "default-deny-networkpolicy.json": ("networking.k8s.io/v1", "NetworkPolicy"),
            "resource-quota.json": ("v1", "ResourceQuota"),
            "baseline-deployment.json": ("apps/v1", "Deployment"),
            "baseline-deployment-v2.json": ("apps/v1", "Deployment"),
        }
        self.assertEqual(
            {path.name for path in FIXTURES.glob("*.json")},
            set(expected) | {"harden-readonly.patch.json"},
        )
        for name, identity in expected.items():
            resource = read_fixture(name)
            self.assertEqual((resource["apiVersion"], resource["kind"]), identity)
            self.assertNotIn("status", resource)
            if identity[1] != "Namespace":
                self.assertEqual(resource["metadata"]["namespace"], NAMESPACE)

    def test_namespace_requires_restricted_pods(self):
        self.assertEqual(self.namespace["metadata"]["name"], NAMESPACE)
        labels = self.namespace["metadata"]["labels"]
        for mode in ("enforce", "audit", "warn"):
            self.assertEqual(labels[f"pod-security.kubernetes.io/{mode}"], "restricted")

    def test_entire_namespace_has_default_deny_both_directions(self):
        self.assertEqual(
            self.network["spec"],
            {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
             "ingress": [], "egress": []},
        )

    def test_baseline_is_bounded_and_has_no_exposed_or_host_resources(self):
        self.assertEqual(self.deployment["metadata"]["name"], "kspm-scope-proof")
        spec = self.deployment["spec"]
        self.assertEqual(spec["replicas"], 2)
        self.assertEqual(spec["strategy"], {
            "type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}
        })
        self.assertEqual(spec["selector"]["matchLabels"]["app.kubernetes.io/name"],
                         spec["template"]["metadata"]["labels"]["app.kubernetes.io/name"])
        pod = spec["template"]["spec"]
        self.assertEqual(set(pod), {"automountServiceAccountToken", "securityContext", "containers"})
        self.assertIs(pod["automountServiceAccountToken"], False)
        self.assertEqual(pod["securityContext"], {
            "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        })
        self.assertEqual(len(pod["containers"]), 1)
        container = pod["containers"][0]
        self.assertEqual(set(container), {"name", "image", "imagePullPolicy", "securityContext", "resources"})
        self.assertEqual(container["name"], "pause")
        self.assertRegex(container["image"],
                         r"^registry\.k8s\.io/pause(?::3\.10\.1)?(?:@sha256:[a-f0-9]{64})?$")
        self.assertNotEqual(container["image"], "registry.k8s.io/pause")
        self.assertEqual(container["securityContext"], {
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": False,
            "capabilities": {"drop": ["ALL"]},
        })

    def test_resource_quota_caps_capacity_and_supports_scale_to_four(self):
        resources = self.deployment["spec"]["template"]["spec"]["containers"][0]["resources"]
        self.assertEqual(resources, {
            "requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"cpu": "50m", "memory": "32Mi"},
        })
        hard = self.quota["spec"]["hard"]
        self.assertEqual(hard, {
            "pods": "6", "requests.cpu": "100m", "requests.memory": "128Mi",
            "limits.cpu": "400m", "limits.memory": "256Mi",
        })
        self.assertGreaterEqual(int(hard["pods"]), 4)
        for category in ("requests", "limits"):
            for resource, suffix in (("cpu", "m"), ("memory", "Mi")):
                per_pod = int(resources[category][resource].removesuffix(suffix))
                capacity = int(hard[f"{category}.{resource}"].removesuffix(suffix))
                self.assertGreaterEqual(capacity, per_pod * int(hard["pods"]))

    def test_hardening_changes_only_root_filesystem_setting(self):
        self.assertEqual(self.patch, [
            {"op": "test", "path": "/spec/template/spec/containers/0/name", "value": "pause"},
            {"op": "replace", "path": READONLY_PATH, "value": True},
        ])
        hardened = apply_hardening_patch(self.deployment, self.patch)
        self.assertEqual(changed_paths(self.deployment, hardened), {READONLY_PATH})
        self.assertIs(hardened["spec"]["template"]["spec"]["containers"][0]
                      ["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertEqual(apply_hardening_patch(hardened, self.patch), hardened)

    def test_hardening_refuses_an_unexpected_container(self):
        modified = copy.deepcopy(self.deployment)
        modified["spec"]["template"]["spec"]["containers"][0]["name"] = "unexpected"
        with self.assertRaises(ValueError):
            apply_hardening_patch(modified, self.patch)

    def test_mutation_check_exposes_an_extra_security_change(self):
        hardened = apply_hardening_patch(self.deployment, self.patch)
        hardened["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
        self.assertEqual(changed_paths(self.deployment, hardened), {
            READONLY_PATH, "/spec/template/spec/automountServiceAccountToken"
        })


if __name__ == "__main__":
    unittest.main()
