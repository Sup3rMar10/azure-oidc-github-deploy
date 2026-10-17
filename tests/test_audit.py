"""Each audit rule fires on the mistake it names and stays quiet on correct configuration."""

import pytest

from entra_guard import Deployment, audit

from .conftest import ROOT, VARS, audit_ids, tf

SUBSCRIPTION = '"/subscriptions/${var.subscription_id}"'
MGMT_GROUP = '"/providers/Microsoft.Management/managementGroups/mg1"'
ONE_RESOURCE = '"${azurerm_resource_group.app.id}/providers/Microsoft.Storage/storageAccounts/st"'


def test_the_shipped_terraform_has_no_findings():
    assert audit(Deployment.from_dir(str(ROOT / "terraform"), VARS)) == []


def test_the_test_helper_document_is_clean_so_every_finding_below_is_the_knob():
    assert audit_ids(tf()) == []


@pytest.mark.parametrize("knob,expected", [
    # federated credentials
    (dict(deploy_subject="repo:${var.github_org}/${var.github_repo}:environment:*"), ["FIC001"]),
    (dict(deploy_subject="repo:${var.github_org}/*"), ["FIC001", "FIC004"]),  # also leaves the repo
    (dict(issuer="https://sts.windows.net/tenant/"), ["FIC002"]),
    (dict(audiences='["api://custom"]'), ["FIC003"]),
    (dict(audiences='["api://AzureADTokenExchange", "api://custom"]'), ["FIC003"]),
    (dict(deploy_subject="repo:attacker/payments:environment:production"), ["FIC004"]),
    (dict(deploy_subject="repo:acme/other:environment:production"), ["FIC004"]),
    (dict(deploy_subject="repo:acme/payments-fork:environment:production"), ["FIC004"]),
    (dict(deploy_subject="repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"), ["FIC005"]),
    # roles and scopes
    (dict(pr_role="Contributor"), ["RBAC004"]),
    (dict(pr_role="Storage Blob Data Contributor"), ["RBAC004"]),
    (dict(deploy_role="Owner"), ["RBAC001"]),
    (dict(deploy_role="User Access Administrator"), ["RBAC001"]),
    (dict(deploy_scope=SUBSCRIPTION), ["RBAC002"]),
    (dict(deploy_scope=MGMT_GROUP), ["RBAC002", "RBAC003"]),
    (dict(deploy_scope='"/"'), ["RBAC002", "RBAC003"]),
    (dict(deploy_role="Owner", deploy_scope=SUBSCRIPTION), ["RBAC001", "RBAC002"]),
])
def test_a_rule_fires_on_the_mistake(knob, expected):
    assert audit_ids(tf(**knob)) == expected


@pytest.mark.parametrize("knob", [
    dict(deploy_scope=ONE_RESOURCE),                                  # narrower than the resource group is fine
    dict(pr_scope=SUBSCRIPTION),                                      # Reader may be wide: it changes nothing
    dict(pr_subject="repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"),  # a branch subject on a read-only identity
    dict(deploy_subject="repo:${var.github_org}/${var.github_repo}:environment:staging"),
])
def test_a_rule_stays_quiet_on_correct_configuration(knob):
    assert audit_ids(tf(**knob)) == []


def test_reader_at_the_root_is_only_a_warning():
    findings = audit(Deployment.from_text(tf(pr_scope='"/"'), VARS))
    assert [(f.id, f.severity) for f in findings] == [("RBAC003", "warn")]


def test_severities():
    by_id = {f.id: f.severity for t in (
        tf(deploy_subject="repo:acme/*", audiences='["x"]', issuer="https://e/"),
        tf(deploy_subject="repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"),
    ) for f in audit(Deployment.from_text(t, VARS))}
    assert by_id["FIC001"] == "error" and by_id["FIC002"] == "error" and by_id["FIC004"] == "error"
    assert by_id["FIC003"] == "warn" and by_id["FIC005"] == "warn"


@pytest.mark.parametrize("rtype", ["azuread_application_password", "azuread_service_principal_password"])
def test_a_client_secret_is_flagged(rtype):
    extra = f'resource "{rtype}" "x" {{ application_id = azuread_application.deploy.id }}'
    assert audit_ids(tf(extra=extra)) == ["APP001"]


def test_the_wildcard_rule_names_the_real_consequence():
    msg = next(f.message for f in audit(Deployment.from_text(tf(deploy_subject="repo:acme/*"), VARS)) if f.id == "FIC001")
    assert "literal" in msg or "exactly" in msg


def test_a_repeated_finding_is_reported_for_each_credential():
    two = tf(extra='''
resource "azuread_application_federated_identity_credential" "second" {
  application_id = azuread_application.deploy.id
  display_name   = "second"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:evil/x:environment:production"
}''')
    assert audit_ids(two) == ["FIC004"]
