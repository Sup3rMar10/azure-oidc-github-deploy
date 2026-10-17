from pathlib import Path

import pytest

from entra_guard import Deployment
from entra_guard.model import DEFAULT_AUDIENCE, GITHUB_ISSUER

ROOT = Path(__file__).resolve().parent.parent
SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-payments"
VARS = {"subscription_id": SUB, "github_org": "acme", "github_repo": "payments", "deploy_environment": "production",
        "resource_group_name": "rg-payments"}


@pytest.fixture(scope="session")
def deployment():
    return Deployment.from_dir(str(ROOT / "terraform"), VARS)


@pytest.fixture(scope="session")
def plan(deployment):
    return deployment.app("plan")


@pytest.fixture(scope="session")
def deploy(deployment):
    return deployment.app("deploy")


def token(sub="repo:acme/payments:environment:production", iss=GITHUB_ISSUER, aud=DEFAULT_AUDIENCE):
    """The claims Entra looks at in a GitHub Actions OIDC token."""
    out = {"iss": iss, "sub": sub, "aud": aud}
    return {k: v for k, v in out.items() if v is not None}


def tf(extra="", pr_role="Reader", deploy_role="Contributor", deploy_scope="azurerm_resource_group.app.id",
       deploy_subject="repo:${var.github_org}/${var.github_repo}:environment:${var.deploy_environment}",
       issuer="https://token.actions.githubusercontent.com", audiences='["api://AzureADTokenExchange"]',
       pr_scope="azurerm_resource_group.app.id", pr_subject="repo:${var.github_org}/${var.github_repo}:pull_request"):
    """A small Terraform document in the same shape as the real one, with knobs for the audit tests."""
    return f'''
resource "azurerm_resource_group" "app" {{
  name     = var.resource_group_name
  location = "westeurope"
}}
resource "azuread_application" "plan" {{ display_name = "plan" }}
resource "azuread_service_principal" "plan" {{ client_id = azuread_application.plan.client_id }}
resource "azuread_application" "deploy" {{ display_name = "deploy" }}
resource "azuread_service_principal" "deploy" {{ client_id = azuread_application.deploy.client_id }}
resource "azuread_application_federated_identity_credential" "plan_pr" {{
  application_id = azuread_application.plan.id
  display_name   = "pr"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "{pr_subject}"
}}
resource "azuread_application_federated_identity_credential" "deploy_env" {{
  application_id = azuread_application.deploy.id
  display_name   = "env"
  audiences      = {audiences}
  issuer         = "{issuer}"
  subject        = "{deploy_subject}"
}}
resource "azurerm_role_assignment" "plan" {{
  scope                = {pr_scope}
  role_definition_name = "{pr_role}"
  principal_id         = azuread_service_principal.plan.object_id
}}
resource "azurerm_role_assignment" "deploy" {{
  scope                = {deploy_scope}
  role_definition_name = "{deploy_role}"
  principal_id         = azuread_service_principal.deploy.object_id
}}
{extra}
'''


def audit_ids(text):
    from entra_guard import audit
    return sorted(f.id for f in audit(Deployment.from_text(text, VARS)))
