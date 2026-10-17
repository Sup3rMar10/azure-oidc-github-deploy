output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "plan_client_id" {
  description = "Set as the repository variable AZURE_PLAN_CLIENT_ID (a client id is an identifier, not a secret)."
  value       = azuread_application.plan.client_id
}

output "deploy_client_id" {
  description = "Set as the repository variable AZURE_DEPLOY_CLIENT_ID."
  value       = azuread_application.deploy.client_id
}
