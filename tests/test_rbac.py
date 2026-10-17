"""The RBAC evaluator: scopes, wildcards, role arithmetic."""

import pytest

from entra_guard import Assignment, allowed, scope_contains

from .conftest import RG, SUB

STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/stpay"
READ = "Microsoft.Storage/storageAccounts/read"
WRITE = "Microsoft.Storage/storageAccounts/write"
GRANT = "Microsoft.Authorization/roleAssignments/write"
BLOB_READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
BLOB_WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"


@pytest.mark.parametrize("scope,resource,expected", [
    ("/", RG, True),
    (f"/subscriptions/{SUB}", RG, True),
    (RG, RG, True),
    (RG, STORAGE, True),
    (RG, f"/subscriptions/{SUB}/resourceGroups/rg-payments2", False),   # a longer name is not a child
    (RG, f"/subscriptions/{SUB}/resourceGroups/rg-payments-prod", False),
    (RG, f"/subscriptions/{SUB}/resourceGroups/rg", False),
    (RG, f"/subscriptions/{SUB}", False),                                 # a parent is not contained by its child
    (RG, "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-payments", False),
    (RG.upper(), STORAGE, True),                                          # resource ids are case-insensitive
    (RG, STORAGE.lower(), True),
    (RG + "/", STORAGE, True),
    (STORAGE, RG, False),
])
def test_scope_containment(scope, resource, expected):
    assert scope_contains(scope, resource) is expected


def test_reader_reads_and_nothing_else():
    a = [Assignment("Reader", RG)]
    assert allowed(a, READ, STORAGE)
    assert allowed(a, "Microsoft.Compute/virtualMachines/read", STORAGE)
    assert not allowed(a, WRITE, STORAGE)
    assert not allowed(a, GRANT, RG)
    assert not allowed(a, BLOB_READ, STORAGE, data=True)  # reading the resource is not reading its data


def test_contributor_writes_but_cannot_grant_access():
    a = [Assignment("Contributor", RG)]
    assert allowed(a, WRITE, STORAGE) and allowed(a, "Microsoft.Compute/virtualMachines/delete", RG)
    assert not allowed(a, GRANT, RG)
    assert not allowed(a, "Microsoft.Authorization/roleAssignments/delete", RG)
    assert not allowed(a, "Microsoft.Authorization/elevateAccess/Action", "/")


def test_contributor_does_not_get_data_plane_access():
    assert not allowed([Assignment("Contributor", RG)], BLOB_READ, STORAGE, data=True)


def test_owner_can_do_everything_in_scope():
    a = [Assignment("Owner", RG)]
    assert allowed(a, GRANT, RG) and allowed(a, WRITE, STORAGE)
    assert not allowed(a, WRITE, f"/subscriptions/{SUB}/resourceGroups/other")


def test_user_access_administrator_grants_but_does_not_deploy():
    a = [Assignment("User Access Administrator", RG)]
    assert allowed(a, GRANT, RG) and allowed(a, READ, STORAGE)
    assert not allowed(a, WRITE, STORAGE)


def test_blob_data_contributor_has_data_access_only_to_blobs():
    a = [Assignment("Storage Blob Data Contributor", STORAGE)]
    assert allowed(a, BLOB_WRITE, STORAGE + "/blobServices/default/containers/c", data=True)
    assert not allowed(a, BLOB_WRITE, RG, data=True)   # the assignment is on one account, the check is one level up
    assert not allowed(a, WRITE, STORAGE)               # and it is not a control-plane writer


def test_assignments_add_together():
    a = [Assignment("Reader", RG), Assignment("Storage Blob Data Contributor", STORAGE)]
    assert allowed(a, READ, STORAGE) and allowed(a, BLOB_WRITE, STORAGE, data=True)
    assert not allowed(a, WRITE, STORAGE)


def test_an_assignment_elsewhere_grants_nothing_here():
    assert not allowed([Assignment("Owner", f"/subscriptions/{SUB}/resourceGroups/other")], READ, STORAGE)


def test_no_assignments_and_unknown_roles_grant_nothing():
    assert not allowed([], READ, STORAGE)
    assert not allowed([Assignment("Made Up Role", "/")], READ, STORAGE)


def test_action_matching_is_case_insensitive_and_whole_string():
    a = [Assignment("Reader", RG)]
    assert allowed(a, "MICROSOFT.STORAGE/STORAGEACCOUNTS/READ", STORAGE)
    assert not allowed(a, "Microsoft.Storage/storageAccounts/readAndDelete", STORAGE)  # `*/read` anchors at the end
