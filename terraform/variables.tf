variable "subscription_id" {
  description = "The subscription that holds the deployment resource group."
  type        = string
}

variable "github_org" {
  description = "The GitHub organisation (or user) that owns the repository."
  type        = string
}

variable "github_repo" {
  description = "The repository whose workflows may deploy."
  type        = string
}

variable "deploy_environment" {
  description = "The GitHub environment whose jobs may deploy. Protect it with required reviewers."
  type        = string
  default     = "production"
}

variable "resource_group_name" {
  description = "The resource group the pipeline deploys into. Its scope is the widest either identity gets."
  type        = string
}

variable "location" {
  type    = string
  default = "westeurope"
}
