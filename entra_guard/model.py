"""Model the token exchange: which GitHub tokens may become which Entra application, and what can they then do?

A federated identity credential lives on ONE application. The workflow names the application (its client id), and
Entra accepts the token only if the token's issuer, subject and audience each equal the values on one of that
application's credentials. A regular credential compares exactly (case-sensitive, no wildcards); the newer
"flexible" credentials, which can match a claim with an expression, are NOT modelled here. Missing claims fail
closed. This is a model of documented behaviour, never compared against a real tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .rbac import Assignment, allowed

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_AUDIENCE = "api://AzureADTokenExchange"


@dataclass(frozen=True)
class Credential:
    name: str
    issuer: str
    subject: str
    audiences: tuple[str, ...]


@dataclass
class App:
    name: str
    credentials: list[Credential] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)


@dataclass
class Exchange:
    accepted: bool
    credential: str | None = None
    reason: str = ""


def exchange(app: App, token: dict) -> Exchange:
    """Would Entra turn this token into an access token for this application?"""
    issuer, subject, audience = token.get("iss"), token.get("sub"), token.get("aud")
    for claim, value in (("iss", issuer), ("sub", subject), ("aud", audience)):
        if not isinstance(value, str) or not value:
            return Exchange(False, None, f"the token has no usable {claim} claim: denied")
    for c in app.credentials:
        if c.issuer == issuer and c.subject == subject and audience in c.audiences:
            return Exchange(True, c.name)
    return Exchange(False, None, "no federated credential on this application matches the issuer, subject and audience exactly")


def can(app: App, token: dict, action: str, resource: str, *, data: bool = False) -> bool:
    """May this token, exchanged for this application, perform the action on the resource? Nothing if not accepted."""
    if not exchange(app, token).accepted:
        return False
    return allowed(app.assignments, action, resource, data=data)


PROBES = {
    "read": ("Microsoft.Storage/storageAccounts/read", False),
    "write": ("Microsoft.Storage/storageAccounts/write", False),
    "grant access": ("Microsoft.Authorization/roleAssignments/write", False),
    "read blob data": ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", True),
}


def capabilities(app: App, token: dict, resource: str) -> list[str]:
    """A short, readable summary of what the token can do to a resource, from a fixed set of probe actions."""
    return [label for label, (action, data) in PROBES.items() if can(app, token, action, resource, data=data)]
