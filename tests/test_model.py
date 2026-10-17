"""The exchange: which tokens does each application accept, and what can they then do?"""

import pytest

from entra_guard import App, Assignment, Credential, can, capabilities, exchange
from entra_guard.model import DEFAULT_AUDIENCE, GITHUB_ISSUER

from .conftest import RG, token

PR = "repo:acme/payments:pull_request"
PROD = "repo:acme/payments:environment:production"


def app(*creds, assignments=()):
    return App("a", [Credential(f"c{i}", *c) for i, c in enumerate(creds)], list(assignments))


EXACT = (GITHUB_ISSUER, PROD, (DEFAULT_AUDIENCE,))


def test_the_exact_issuer_subject_and_audience_is_accepted():
    ex = exchange(app(EXACT), token())
    assert ex.accepted and ex.credential == "c0"


@pytest.mark.parametrize("sub", [
    "repo:acme/payments:environment:Production",     # case matters
    "repo:Acme/payments:environment:production",
    "repo:acme/payments:environment:production ",    # one trailing space
    "repo:acme/payments:environment:production/",
    "repo:acme/payments:environment:prod",
    "repo:acme/payments:environment:production-eu",
    "repo:acme/payments:environment:staging",
    "repo:acme/payments:pull_request",
    "repo:acme/payments:ref:refs/heads/main",
    "repo:attacker/payments:environment:production",  # a fork or a copy of the repo under another owner
    "repo:acme/payments-fork:environment:production",
    "repo:acme/payments",
    "",
])
def test_any_other_subject_is_refused(sub):
    assert not exchange(app(EXACT), token(sub=sub)).accepted


def test_a_wildcard_in_a_credential_is_just_text_not_a_pattern():
    wild = app((GITHUB_ISSUER, "repo:acme/payments:environment:*", (DEFAULT_AUDIENCE,)))
    assert not exchange(wild, token()).accepted
    assert exchange(wild, token(sub="repo:acme/payments:environment:*")).accepted  # only the literal star


@pytest.mark.parametrize("iss", ["https://token.actions.githubusercontent.com/", "http://token.actions.githubusercontent.com",
                                 "https://evil.example/", "https://sts.windows.net/tenant/"])
def test_the_issuer_must_match_exactly(iss):
    assert not exchange(app(EXACT), token(iss=iss)).accepted


@pytest.mark.parametrize("aud", ["sts.amazonaws.com", "api://AzureADTokenExchange/", "api://azureadtokenexchange",
                                 "https://github.com/acme"])
def test_the_audience_must_be_one_the_credential_lists(aud):
    assert not exchange(app(EXACT), token(aud=aud)).accepted


def test_a_credential_with_two_audiences_accepts_either():
    two = app((GITHUB_ISSUER, PROD, (DEFAULT_AUDIENCE, "api://other")))
    assert exchange(two, token(aud="api://other")).accepted
    assert not exchange(two, token(aud="api://third")).accepted


@pytest.mark.parametrize("missing", ["iss", "sub", "aud"])
def test_a_token_missing_a_claim_is_refused(missing):
    t = token()
    del t[missing]
    ex = exchange(app(EXACT), t)
    assert not ex.accepted and missing in ex.reason


@pytest.mark.parametrize("bad", [None, "", 5, ["x"]])
def test_a_claim_of_the_wrong_type_is_refused(bad):
    assert not exchange(app(EXACT), {**token(), "sub": bad}).accepted


def test_all_three_values_must_match_the_same_credential():
    # issuer from one credential, subject from another: no single credential matches
    mixed = app(("https://other.example", PROD, (DEFAULT_AUDIENCE,)), (GITHUB_ISSUER, "repo:x/y:pull_request", (DEFAULT_AUDIENCE,)))
    assert not exchange(mixed, token()).accepted


def test_an_application_with_no_credentials_accepts_nothing():
    assert not exchange(app(), token()).accepted


def test_the_first_matching_credential_is_reported():
    two = app((GITHUB_ISSUER, PR, (DEFAULT_AUDIENCE,)), (GITHUB_ISSUER, PROD, (DEFAULT_AUDIENCE,)))
    assert exchange(two, token()).credential == "c1"


# --- after the exchange, RBAC decides ------------------------------------------------------------------------

def test_an_accepted_token_can_do_only_what_the_role_allows():
    a = app(EXACT, assignments=[Assignment("Reader", RG)])
    assert can(a, token(), "Microsoft.Storage/storageAccounts/read", RG + "/providers/Microsoft.Storage/storageAccounts/s")
    assert not can(a, token(), "Microsoft.Storage/storageAccounts/write", RG)


def test_a_refused_token_can_do_nothing_even_with_owner():
    a = app(EXACT, assignments=[Assignment("Owner", "/")])
    assert not can(a, token(sub="repo:attacker/payments:environment:production"), "Microsoft.Storage/storageAccounts/read", RG)
    assert capabilities(a, token(sub="nope"), RG) == []


# --- the real Terraform, every token shape against both applications ------------------------------------------

ORG, REPO = "acme", "payments"
MATRIX = [
    # (subject, aud, plan accepted, deploy accepted)
    (f"repo:{ORG}/{REPO}:pull_request", DEFAULT_AUDIENCE, True, False),
    (f"repo:{ORG}/{REPO}:environment:production", DEFAULT_AUDIENCE, False, True),
    (f"repo:{ORG}/{REPO}:environment:staging", DEFAULT_AUDIENCE, False, False),
    (f"repo:{ORG}/{REPO}:ref:refs/heads/main", DEFAULT_AUDIENCE, False, False),
    (f"repo:{ORG}/{REPO}:ref:refs/tags/v1", DEFAULT_AUDIENCE, False, False),
    (f"repo:attacker/{REPO}:pull_request", DEFAULT_AUDIENCE, False, False),
    (f"repo:attacker/{REPO}:environment:production", DEFAULT_AUDIENCE, False, False),
    (f"repo:{ORG}/other:environment:production", DEFAULT_AUDIENCE, False, False),
    (f"repo:{ORG}/{REPO}:pull_request", "sts.amazonaws.com", False, False),
    (f"repo:{ORG}/{REPO}:environment:production", "sts.amazonaws.com", False, False),
    (f"repo:{ORG}/{REPO}:environment:Production", DEFAULT_AUDIENCE, False, False),
    ("", DEFAULT_AUDIENCE, False, False),
]


@pytest.mark.parametrize("sub,aud,plan_ok,deploy_ok", MATRIX)
def test_every_token_shape_against_the_real_terraform(plan, deploy, sub, aud, plan_ok, deploy_ok):
    t = token(sub=sub, aud=aud)
    assert exchange(plan, t).accepted is plan_ok
    assert exchange(deploy, t).accepted is deploy_ok


def test_no_token_is_accepted_by_both_applications(plan, deploy):
    for sub, aud, *_ in MATRIX:
        t = token(sub=sub, aud=aud)
        assert not (exchange(plan, t).accepted and exchange(deploy, t).accepted)


def test_what_each_identity_can_then_do(plan, deploy):
    assert capabilities(plan, token(sub=f"repo:{ORG}/{REPO}:pull_request"), RG) == ["read"]
    assert capabilities(deploy, token(), RG) == ["read", "write"]  # Contributor: no role assignments, no blob data
