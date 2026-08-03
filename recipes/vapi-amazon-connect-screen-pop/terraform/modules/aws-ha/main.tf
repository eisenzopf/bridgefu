locals {
  required_parameters = toset([
    "ArtifactBucket",
    "BridgefuImageUri",
    "ConnectInstanceArn",
    "LookupArtifactKey",
    "LookupArtifactVersion",
    "NestedTemplateBaseUrl",
    "PrepareArtifactKey",
    "PrepareArtifactVersion",
    "PrivateTlsSecretArn",
    "ProvisionerArtifactKey",
    "ProvisionerArtifactVersion",
    "PublicHostedZoneId",
    "RuntimeArtifactKey",
    "RuntimeArtifactSha256",
    "RuntimeArtifactVersion",
    "RuntimeProfile",
    "SipHostname",
    "TargetContactFlowArn",
    "TransferArtifactKey",
    "TransferArtifactVersion",
    "VapiApiKeySecretArn",
  ])

  ownership_tags = {
    Project             = "bridgefu-recipe"
    ManagedBy           = "bridgefu-terraform"
    BridgefuExecutionId = var.deployment_id
    BridgefuRecipe      = "vapi-amazon-connect-screen-pop@1"
  }
}

resource "aws_cloudformation_stack" "recipe" {
  name = var.stack_name

  template_url = var.template_url
  parameters = merge(
    var.parameters,
    { DeploymentId = var.deployment_id }
  )
  capabilities = [
    "CAPABILITY_AUTO_EXPAND",
    "CAPABILITY_NAMED_IAM",
  ]
  iam_role_arn       = var.cloudformation_service_role_arn == "" ? null : var.cloudformation_service_role_arn
  notification_arns  = var.notification_arns
  timeout_in_minutes = 150
  tags               = merge(var.tags, local.ownership_tags)

  lifecycle {
    precondition {
      condition     = length(setsubtract(local.required_parameters, toset(keys(var.parameters)))) == 0
      error_message = "parameters is missing one or more required High Availability CloudFormation inputs."
    }

    precondition {
      condition     = var.parameters["RuntimeProfile"] == "HighAvailability"
      error_message = "The HA module requires RuntimeProfile=HighAvailability."
    }

    precondition {
      condition     = can(regex("@sha256:[0-9a-f]{64}$", var.parameters["BridgefuImageUri"]))
      error_message = "BridgefuImageUri must be an immutable digest reference."
    }

    precondition {
      condition     = can(regex("^[0-9a-f]{64}$", var.parameters["RuntimeArtifactSha256"]))
      error_message = "RuntimeArtifactSha256 must be an exact SHA-256 digest."
    }

    precondition {
      condition     = can(regex("^arn:aws[-a-z0-9]*:secretsmanager:", var.parameters["PrivateTlsSecretArn"]))
      error_message = "PrivateTlsSecretArn must identify the reviewed private HA mTLS bundle."
    }
  }
}
