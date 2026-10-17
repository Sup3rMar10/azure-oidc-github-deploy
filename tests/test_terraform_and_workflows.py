"""The Terraform is read correctly, and the pipeline's own permissions are tested too."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml

from entra_guard import Deployment

from .conftest import RG, ROOT, VARS

WORKFLOWS = ROOT / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))


# --- the Terraform reader ------------------------------------------------------------------------------------

def test_two_applications_one_credential_and_one_assignment_each(deployment):
    apps = deployment.apps()
    assert [len(a.credentials) for a in apps] == [1, 1]
    assert [len(a.assignments) for a in apps] == [1, 1]


def test_subjects_are_resolved_to_exact_strings(plan, deploy):
    assert plan.credentials[0].subject == "repo:acme/payments:pull_request"
    assert deploy.credentials[0].subject == "repo:acme/payments:environment:production"
    assert deploy.credentials[0].audiences == ("api://AzureADTokenExchange",)


def test_assignments_are_resolved_to_the_resource_group_and_the_right_role(plan, deploy):
    assert [(a.role, a.scope) for a in plan.assignments] == [("Reader", RG)]
    assert [(a.role, a.scope) for a in deploy.assignments] == [("Contributor", RG)]


def test_nothing_is_left_unresolved_in_the_model(deployment):
    assert "<" not in json.dumps([asdict(a) for a in deployment.apps()])


def test_a_reference_the_reader_does_not_understand_stays_visible():
    text = 'resource "azurerm_role_assignment" "x" { scope = azurerm_key_vault.kv.id }'
    d = Deployment.from_text(text, VARS)
    assert d.of_type("azurerm_role_assignment")[0][1]["scope"] == "<azurerm_key_vault.kv.id>"


def test_changing_a_variable_changes_the_trusted_subject():
    d = Deployment.from_dir(str(ROOT / "terraform"), {**VARS, "github_repo": "ledger", "deploy_environment": "prod"})
    assert d.app("deploy").credentials[0].subject == "repo:acme/ledger:environment:prod"


def test_the_terraform_pins_providers():
    text = (ROOT / "terraform" / "versions.tf").read_text(encoding="utf-8")
    assert 'version = "~> 3.0"' in text and 'version = "~> 4.0"' in text


# --- the workflows -------------------------------------------------------------------------------------------

def load(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def azure_jobs(wf):
    return {n: j for n, j in wf["jobs"].items() if any("azure/login" in str(s.get("uses", "")) for s in j.get("steps", []))}


def test_there_are_workflows_to_check():
    assert {p.name for p in FILES} >= {"ci.yml", "deploy.yml"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_client_secret_or_credentials_json_anywhere(path):
    text = path.read_text(encoding="utf-8")
    for needle in ("creds:", "AZURE_CREDENTIALS", "client-secret", "ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET", "clientSecret"):
        assert needle not in text


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_token_permissions_default_to_read_only(path):
    assert load(path).get("permissions") == {"contents": "read"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_only_jobs_that_log_in_to_azure_may_mint_an_oidc_token(path):
    wf = load(path)
    allowed = set(azure_jobs(wf))
    for name, job in wf["jobs"].items():
        assert (job.get("permissions", {}).get("id-token") == "write") == (name in allowed), f"{path.name}:{name}"


def test_identifiers_come_from_variables_never_literals():
    wf = load(WORKFLOWS / "deploy.yml")
    for job in azure_jobs(wf).values():
        for step in job["steps"]:
            if "azure/login" in str(step.get("uses", "")):
                for key in ("client-id", "tenant-id", "subscription-id"):
                    assert step["with"][key].startswith("${{ vars."), key


def test_pull_requests_get_the_plan_application_and_pushes_to_main_the_deploy_application():
    wf = load(WORKFLOWS / "deploy.yml")
    plan, deploy = wf["jobs"]["plan"], wf["jobs"]["deploy"]
    assert "github.event_name == 'pull_request'" in plan["if"] and "AZURE_PLAN_CLIENT_ID" in plan["if"]
    assert "github.event_name == 'push'" in deploy["if"] and "AZURE_DEPLOY_CLIENT_ID" in deploy["if"]
    assert deploy["environment"] == "production" and "environment" not in plan
    plan_login = next(s for s in plan["steps"] if "azure/login" in str(s.get("uses", "")))
    deploy_login = next(s for s in deploy["steps"] if "azure/login" in str(s.get("uses", "")))
    assert "AZURE_PLAN_CLIENT_ID" in plan_login["with"]["client-id"]
    assert "AZURE_DEPLOY_CLIENT_ID" in deploy_login["with"]["client-id"]


def test_the_deploy_environment_matches_the_one_terraform_trusts():
    wf = load(WORKFLOWS / "deploy.yml")
    assert wf["jobs"]["deploy"]["environment"] == VARS["deploy_environment"]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_pull_request_target_is_never_used(path):
    assert "pull_request_target" not in path.read_text(encoding="utf-8")
