"""A small Azure RBAC evaluator: given role assignments, may this identity perform an action on a resource?

Documented behaviour modelled: an assignment applies to its scope and everything below it; the permissions of all
applicable assignments are added together; each role grants `actions` minus `notActions` (control plane) and
`dataActions` minus `notDataActions` (data plane), where `*` matches any run of characters. Not modelled: deny
assignments, conditions on assignments, PIM, and the full built-in role definitions (the table below is abridged
to what this repository needs, so a real role may allow or exclude more).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ROLES: dict[str, dict[str, list[str]]] = {
    "Reader": {"actions": ["*/read"], "notActions": [], "dataActions": [], "notDataActions": []},
    "Contributor": {
        "actions": ["*"],
        # Contributor can do everything except manage access. This is the abridged list.
        "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write",
                       "Microsoft.Authorization/elevateAccess/Action"],
        "dataActions": [], "notDataActions": [],
    },
    "Owner": {"actions": ["*"], "notActions": [], "dataActions": [], "notDataActions": []},
    "User Access Administrator": {
        "actions": ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"],
        "notActions": [], "dataActions": [], "notDataActions": [],
    },
    "Storage Blob Data Contributor": {
        "actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/delete",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/write"],
        "notActions": [],
        "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
        "notDataActions": [],
    },
}

# Roles that can change who has access, or do everything: a pipeline identity should not hold them.
ACCESS_ADMIN_ROLES = {"Owner", "User Access Administrator"}
BROAD_ROLES = {"Owner", "Contributor", "User Access Administrator"}


@dataclass(frozen=True)
class Assignment:
    role: str
    scope: str  # "/", "/subscriptions/<id>", ".../resourceGroups/<rg>", or a resource id


def _norm(path: str) -> str:
    return "/" + "/".join(p for p in path.lower().split("/") if p)


def scope_contains(scope: str, resource: str) -> bool:
    """True if `resource` is the scope itself or below it. Compared by whole path segments, case-insensitively."""
    s, r = _norm(scope), _norm(resource)
    return s == "/" or r == s or r.startswith(s + "/")


def _pattern(p: str) -> re.Pattern:
    return re.compile("^" + ".*".join(re.escape(part) for part in p.lower().split("*")) + "$")


def _matches(action: str, patterns: list[str]) -> bool:
    return any(_pattern(p).match(action.lower()) for p in patterns)


def allowed(assignments: list[Assignment], action: str, resource: str, *, data: bool = False) -> bool:
    """Is `action` granted on `resource` by at least one applicable assignment?"""
    grant, deny = ("dataActions", "notDataActions") if data else ("actions", "notActions")
    for a in assignments:
        role = ROLES.get(a.role)
        if role is None or not scope_contains(a.scope, resource):
            continue
        if _matches(action, role[grant]) and not _matches(action, role[deny]):
            return True
    return False
