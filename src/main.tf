locals {
  enabled     = module.this.enabled
  account_map = module.account_map.outputs.full_account_map

  current_account_id                     = one(data.aws_caller_identity.this[*].account_id)
  org_delegated_administrator_account_id = local.account_map[var.delegated_administrator_account_name]

  unused_access_exclusion_account_names         = flatten([for e in var.unused_access_exclusions : e.account_names])
  unused_access_exclusion_unknown_account_names = [for name in local.unused_access_exclusion_account_names : name if !contains(keys(local.account_map), name)]
  unused_access_exclusion_account_ids           = [for name in local.unused_access_exclusion_account_names : lookup(local.account_map, name, null)]
}

data "aws_caller_identity" "this" {
  count = local.enabled ? 1 : 0
}

# Create the service-linked role in the management account
# This is required before organization-level analyzers can be created from delegated admin
resource "aws_iam_service_linked_role" "access_analyzer" {
  count = local.enabled && var.service_linked_role_enabled && var.organizations_delegated_administrator_enabled ? 1 : 0

  aws_service_name = "access-analyzer.amazonaws.com"
  description      = "Service-linked role for AWS Access Analyzer"
}

resource "aws_accessanalyzer_analyzer" "organization" {
  count = local.enabled && var.accessanalyzer_organization_enabled ? 1 : 0

  analyzer_name = format("%s-organization", module.this.id)
  type          = "ORGANIZATION"

  tags = module.this.tags
}

resource "aws_accessanalyzer_analyzer" "organization_unused_access" {
  count = local.enabled && var.accessanalyzer_organization_unused_access_enabled ? 1 : 0

  analyzer_name = format("%s-organization-unused-access", module.this.id)
  type          = "ORGANIZATION_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age

      dynamic "analysis_rule" {
        for_each = length(var.unused_access_exclusions) > 0 ? [1] : []
        content {
          dynamic "exclusion" {
            for_each = var.unused_access_exclusions
            content {
              account_ids   = [for name in exclusion.value.account_names : local.account_map[name]]
              resource_tags = exclusion.value.resource_tags
            }
          }
        }
      }
    }
  }

  tags = module.this.tags

  lifecycle {
    precondition {
      condition     = length(local.unused_access_exclusion_unknown_account_names) == 0
      error_message = "`unused_access_exclusions` account names not found in the account map: ${join(", ", local.unused_access_exclusion_unknown_account_names)}"
    }
    precondition {
      condition     = !contains(local.unused_access_exclusion_account_ids, local.org_delegated_administrator_account_id)
      error_message = "`unused_access_exclusions` cannot exclude the analyzer owner account (`delegated_administrator_account_name`): AWS rejects it."
    }
  }
}

# Delegate Access Analyzer to the administrator account (usually the security account)
resource "aws_organizations_delegated_administrator" "default" {
  count = local.enabled && var.organizations_delegated_administrator_enabled ? 1 : 0

  account_id        = local.org_delegated_administrator_account_id
  service_principal = var.accessanalyzer_service_principal
}
