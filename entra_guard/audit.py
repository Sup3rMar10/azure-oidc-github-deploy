"""Audit the Terraform for the mistakes that make keyless deployment unsafe."""

from __future__ import annotations

from dataclasses import dataclass

from .model import DEFAULT_AUDIENCE, GITHUB_ISSUER
from .rbac import ACCESS_ADMIN_ROLES, BROAD_ROLES, allowed
from .tf import Deployment

# Actions that only a role able to change something grants. A pull-request identity must hold none of them.
WRITE_PROBES = [("Microsoft.Resources/deployments/write", False), ("Microsoft.Storage/storageAccounts/write", False),
                ("Microsoft.Authorization/roleAssignments/write", False),
                ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", True)]


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str  # "error" fails the audit, "warn" only prints
    message: str


def _level(scope: str) -> str:
    """root, management group, subscription, resource group or resource: how wide an assignment reaches."""
    parts = [p.lower() for p in scope.split("/") if p]
    if not parts:
        return "root"
    if parts[:3] == ["providers", "microsoft.management", "managementgroups"]:
        return "management group"
    if len(parts) == 2 and parts[0] == "subscriptions":
        return "subscription"
    if len(parts) == 4 and parts[0] == "subscriptions" and parts[2] == "resourcegroups":
        return "resource group"
    return "resource"


def _writes(app) -> bool:
    return any(allowed(app.assignments, a, scope, data=d) for a, d in WRITE_PROBES for scope in {x.scope for x in app.assignments})


def audit(d: Deployment) -> list[Finding]:
    out: list[Finding] = []
    prefix = f"repo:{d.variables.get('github_org', '<org>')}/{d.variables.get('github_repo', '<repo>')}:"
    for rtype in ("azuread_application_password", "azuread_service_principal_password"):
        for _ in d.of_type(rtype):
            out.append(Finding("APP001", "error", f"{rtype} creates a long-lived secret; federated credentials need none"))
    for app in d.apps():
        for c in app.credentials:
            where = f"{app.name} / {c.name}"
            if "*" in c.subject:
                out.append(Finding("FIC001", "error", f"{where}: subject {c.subject!r} has a wildcard; a regular credential compares "
                                                      "exactly, so this matches the literal text and never what was meant"))
            if c.issuer != GITHUB_ISSUER:
                out.append(Finding("FIC002", "error", f"{where}: issuer is {c.issuer!r}, not GitHub's {GITHUB_ISSUER}"))
            if c.audiences != (DEFAULT_AUDIENCE,):
                out.append(Finding("FIC003", "warn", f"{where}: audiences {list(c.audiences)} differ from the default {DEFAULT_AUDIENCE}"))
            if not c.subject.startswith(prefix):
                out.append(Finding("FIC004", "error", f"{where}: subject {c.subject!r} is not scoped to {prefix}*, "
                                                      "so it trusts another repository or organisation"))
            if ":ref:refs/heads/" in c.subject and _writes(app):
                out.append(Finding("FIC005", "warn", f"{where}: a branch subject lets anyone who can push that branch deploy; "
                                                     "use an environment with required reviewers"))
            if c.subject.endswith(":pull_request") and _writes(app):
                out.append(Finding("RBAC004", "error", f"{where}: pull-request tokens can change resources; "
                                                       "a contributor could do it from a workflow edit in a PR"))
        for a in app.assignments:
            where = f"{app.name}: {a.role} at {a.scope}"
            if a.role in ACCESS_ADMIN_ROLES:
                out.append(Finding("RBAC001", "error", f"{where}: a pipeline identity must not be able to grant access"))
            if a.role in BROAD_ROLES and _level(a.scope) in {"root", "management group", "subscription"}:
                out.append(Finding("RBAC002", "error", f"{where}: wider than one resource group"))
            if _level(a.scope) in {"root", "management group"}:
                out.append(Finding("RBAC003", "warn", f"{where}: assigned at the root or a management group"))
    return out
