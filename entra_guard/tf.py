"""Read this repository's Terraform into the model: applications, their federated credentials and role assignments.

Only what is needed is resolved: var.X and references between these resources (an application's id, client id,
its service principal's object id, the resource group's id). Anything else stays a visible <ref>, so a test notices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

from .model import App, Credential
from .rbac import Assignment

_REF = re.compile(r"\$\{([^}]+)\}")


def _clean(x):
    if isinstance(x, str):
        return x[1:-1] if len(x) >= 2 and x.startswith('"') and x.endswith('"') else x
    if isinstance(x, dict):
        return {_clean(k): _clean(v) for k, v in x.items() if not str(k).startswith("__")}
    if isinstance(x, list):
        return [_clean(i) for i in x]
    return x


@dataclass
class Deployment:
    resources: dict[tuple[str, str], dict]
    variables: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_text(cls, text: str, variables: dict[str, str] | None = None) -> "Deployment":
        parsed = hcl2.loads(text)
        resources: dict[tuple[str, str], dict] = {}
        for block in parsed.get("resource", []):
            for rtype, named in block.items():
                for name, attrs in named.items():
                    resources[(_clean(rtype), _clean(name))] = _clean(attrs)
        return cls(resources, variables or {})

    @classmethod
    def from_dir(cls, path: str, variables: dict[str, str]) -> "Deployment":
        text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(Path(path).glob("*.tf")))
        return cls.from_text(text, variables)

    # --- resolving -------------------------------------------------------------------------------

    def _ref(self, expr: str) -> str:
        if expr.startswith("var."):
            return self.variables.get(expr[4:], f"<{expr}>")
        parts = expr.split(".")
        if len(parts) == 3:
            rtype, name, attr = parts
            res = self.resources.get((rtype, name))
            if res is None:
                return f"<{expr}>"
            if rtype == "azuread_application":
                return {"id": f"app:{name}", "client_id": f"client:{name}", "object_id": f"app:{name}"}.get(attr, f"<{expr}>")
            if rtype == "azuread_service_principal" and attr == "object_id":
                return f"sp:{name}"
            if rtype == "azurerm_resource_group" and attr == "id":
                return f"/subscriptions/{self.variables.get('subscription_id', '<subscription>')}/resourceGroups/{self.resolve(res['name'])}"
            if attr in res:
                return self.resolve(res[attr])
        return f"<{expr}>"

    def resolve(self, value):
        if isinstance(value, str):
            return _REF.sub(lambda m: self._ref(m.group(1)), value)
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        return value

    def of_type(self, rtype: str) -> list[tuple[str, dict]]:
        return [(n, self.resolve(a)) for (t, n), a in self.resources.items() if t == rtype]

    # --- the model ---------------------------------------------------------------------------------

    def apps(self) -> list[App]:
        apps = {n: App(name=a.get("display_name", n)) for n, a in self.of_type("azuread_application")}
        sp_to_app = {n: sp["client_id"].removeprefix("client:") for n, sp in self.of_type("azuread_service_principal")}
        for n, c in self.of_type("azuread_application_federated_identity_credential"):
            key = c["application_id"].removeprefix("app:")
            apps[key].credentials.append(Credential(n, c["issuer"], c["subject"], tuple(c["audiences"])))
        for _, ra in self.of_type("azurerm_role_assignment"):
            sp = ra["principal_id"].removeprefix("sp:")
            apps[sp_to_app[sp]].assignments.append(Assignment(ra["role_definition_name"], ra["scope"]))
        return list(apps.values())

    def app(self, key: str) -> App:
        """An application by its Terraform name (for example "plan" or "deploy")."""
        apps = {n: a for n, a in zip([n for n, _ in self.of_type("azuread_application")], self.apps())}
        return apps[key]
