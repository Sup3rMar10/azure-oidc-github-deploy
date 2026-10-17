"""python -m entra_guard [terraform-dir] [--org ORG --repo REPO]: audit the Terraform, then show which GitHub token can do what."""

from __future__ import annotations

import argparse

from . import Deployment, audit, capabilities, exchange
from .model import DEFAULT_AUDIENCE, GITHUB_ISSUER


def token(repository: str, *, kind: str, value: str = "", aud: str = DEFAULT_AUDIENCE) -> dict:
    """The claims of a GitHub Actions OIDC token for the subject forms GitHub documents."""
    suffix = {"pull_request": ":pull_request", "environment": f":environment:{value}", "ref": f":ref:{value}"}[kind]
    return {"iss": GITHUB_ISSUER, "sub": f"repo:{repository}{suffix}", "aud": aud}


def scenarios(org: str, repo: str) -> list[tuple[str, dict]]:
    mine = f"{org}/{repo}"
    return [
        ("pull request in the repo", token(mine, kind="pull_request")),
        ("job in the production environment", token(mine, kind="environment", value="production")),
        ("job in the staging environment", token(mine, kind="environment", value="staging")),
        ("push to main (no environment)", token(mine, kind="ref", value="refs/heads/main")),
        ("fork with the same repo name", token(f"attacker/{repo}", kind="environment", value="production")),
        ("another repo in the same org", token(f"{org}/other", kind="environment", value="production")),
        ("right subject, wrong audience", token(mine, kind="environment", value="production", aud="sts.amazonaws.com")),
    ]


def _cell(app, tok: dict, resource: str) -> str:
    if not exchange(app, tok).accepted:
        return "denied"
    return ", ".join(capabilities(app, tok, resource)) or "accepted, can do nothing"


def main() -> int:
    p = argparse.ArgumentParser(prog="entra_guard")
    p.add_argument("terraform", nargs="?", default="terraform")
    p.add_argument("--org", default="acme")
    p.add_argument("--repo", default="payments")
    a = p.parse_args()
    d = Deployment.from_dir(a.terraform, {"subscription_id": "00000000-0000-0000-0000-000000000000", "github_org": a.org,
                                          "github_repo": a.repo, "deploy_environment": "production",
                                          "resource_group_name": "rg-payments"})
    findings = audit(d)
    print(f"audit: {'no findings' if not findings else str(len(findings)) + ' finding(s)'}")
    for f in findings:
        print(f"  [{f.severity}] {f.id}: {f.message}")
    rg = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-payments"
    apps = [d.app("plan"), d.app("deploy")]
    print()
    print(f"  {'token':<36} {'plan app':<12} deploy app")
    for label, tok in scenarios(a.org, a.repo):
        plan, deploy = (_cell(app, tok, rg) for app in apps)
        print(f"  {label:<36} {plan:<12} {deploy}")
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
