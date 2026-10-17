# Two identities, no secrets:
#   plan   - what pull requests use. Reader on one resource group.
#   deploy - what the protected `production` environment uses. Contributor on the same resource group.
# A federated credential lets a GitHub Actions token become the application's service principal. Azure compares
# the token's issuer, subject and audience with the credential, and (for a regular credential) only by exact value.

data "azuread_client_config" "current" {}

resource "azurerm_resource_group" "app" {
  name     = var.resource_group_name
  location = var.location
}

resource "azuread_application" "plan" {
  display_name = "github-${var.github_repo}-plan"
}

resource "azuread_service_principal" "plan" {
  client_id = azuread_application.plan.client_id
}

resource "azuread_application" "deploy" {
  display_name = "github-${var.github_repo}-deploy"
}

resource "azuread_service_principal" "deploy" {
  client_id = azuread_application.deploy.client_id
}

# Pull requests, from this repository only (a fork's token has a different subject).
resource "azuread_application_federated_identity_credential" "plan_pull_request" {
  application_id = azuread_application.plan.id
  display_name   = "github-pull-request"
  description    = "Pull requests in ${var.github_org}/${var.github_repo}"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_org}/${var.github_repo}:pull_request"
}

# One exact identity: jobs that run in this repository's production environment (and so passed its protection rules).
resource "azuread_application_federated_identity_credential" "deploy_environment" {
  application_id = azuread_application.deploy.id
  display_name   = "github-environment-${var.deploy_environment}"
  description    = "Jobs in the ${var.deploy_environment} environment of ${var.github_org}/${var.github_repo}"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_org}/${var.github_repo}:environment:${var.deploy_environment}"
}

resource "azurerm_role_assignment" "plan_reader" {
  scope                = azurerm_resource_group.app.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.plan.object_id
}

resource "azurerm_role_assignment" "deploy_contributor" {
  scope                = azurerm_resource_group.app.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.deploy.object_id
}
