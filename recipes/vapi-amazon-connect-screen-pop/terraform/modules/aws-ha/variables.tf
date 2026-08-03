variable "deployment_id" {
  description = "Stable lowercase recipe deployment identifier."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.deployment_id))
    error_message = "deployment_id must be 3-24 lowercase letters, digits, or hyphens."
  }
}

variable "stack_name" {
  description = "CloudFormation stack name owned through this Terraform module."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9-]{0,127}$", var.stack_name))
    error_message = "stack_name must be a valid CloudFormation stack name."
  }
}

variable "template_url" {
  description = "Immutable HTTPS URL for the signed canonical recipe root template."
  type        = string

  validation {
    condition = (
      can(regex("^https://[^[:space:]?#]+/[^/[:space:]?#]+\\.ya?ml(?:\\?[^#[:space:]]+)?$", var.template_url)) &&
      !can(regex("^https://[^/@]+:[^/@]+@", var.template_url))
    )
    error_message = "template_url must be a credential-free HTTPS URL naming a YAML template."
  }
}

variable "parameters" {
  description = "Exact High Availability CloudFormation parameter map from the immutable release and customer inputs."
  type        = map(string)
  sensitive   = true

  validation {
    condition = alltrue([
      for key, value in var.parameters :
      can(regex("^[A-Za-z][A-Za-z0-9]{0,254}$", key)) &&
      length(value) <= 4096 &&
      !can(regex("[\\r\\n\\x00]", value))
    ])
    error_message = "CloudFormation parameters must have bounded canonical keys and single-line values."
  }
}

variable "cloudformation_service_role_arn" {
  description = "Optional reviewed CloudFormation service-role ARN. Empty uses the Terraform caller."
  type        = string
  default     = ""

  validation {
    condition = (
      var.cloudformation_service_role_arn == "" ||
      can(regex("^arn:aws[-a-z0-9]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.cloudformation_service_role_arn))
    )
    error_message = "cloudformation_service_role_arn must be empty or an IAM role ARN."
  }
}

variable "notification_arns" {
  description = "Optional existing SNS topics for CloudFormation stack events."
  type        = list(string)
  default     = []

  validation {
    condition = length(var.notification_arns) <= 5 && alltrue([
      for arn in var.notification_arns :
      can(regex("^arn:aws[-a-z0-9]*:sns:[-a-z0-9]+:[0-9]{12}:[A-Za-z0-9_-]+$", arn))
    ])
    error_message = "notification_arns must contain at most five SNS topic ARNs."
  }
}

variable "tags" {
  description = "Additional non-authoritative tags. Reserved Bridgefu ownership tags cannot be overridden."
  type        = map(string)
  default     = {}

  validation {
    condition = length(setintersection(
      toset(keys(var.tags)),
      toset(["Project", "ManagedBy", "BridgefuExecutionId", "BridgefuRecipe"])
    )) == 0
    error_message = "tags cannot override Bridgefu ownership tags."
  }
}
