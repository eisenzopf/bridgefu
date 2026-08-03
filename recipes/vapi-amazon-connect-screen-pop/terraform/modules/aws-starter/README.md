# Bridgefu AWS Starter Terraform module

This module gives Terraform-managed AWS estates the exact same application
contract as Bridgefu's canonical Starter Production CloudFormation template. It
manages one `aws_cloudformation_stack` rather than duplicating IAM, Connect,
Lambda, DynamoDB, Vapi, runtime, alarm, and deletion logic in a second codebase.
That makes input, output, update, rollback, readiness, and ownership behavior
identical across Launch Stack, the Bridgefu CLI, and Terraform.

Use only a signed, immutable recipe release. Supply the published template URL
and exact versioned artifact parameters; never point this module at a branch or
mutable object key.

```hcl
module "bridgefu_support" {
  source = "./recipes/vapi-amazon-connect-screen-pop/terraform/modules/aws-starter"

  deployment_id = "support"
  stack_name     = "bridgefu-support"
  template_url   = var.bridgefu_release_template_url
  parameters     = var.bridgefu_recipe_parameters

  tags = {
    Environment = "production"
    Owner       = "contact-center"
  }
}
```

The supplied parameter map includes the existing Amazon Connect instance ARN
and customer target-flow ARN. The nested application creates only its own
wrapper/guide flows and Lambda association; it never updates or deletes the
supplied target flow or instance.

Before an intentional `terraform destroy`, confirm active calls are drained,
review the complete plan, and use the deployment ID in the change record.
Terraform's normal interactive destroy confirmation remains in force. Recipe
data uses the CloudFormation `DataRetentionMode`; release artifacts remain
publisher-owned.

The optional CloudFront test page is selected through the same CloudFormation
parameters and remains off by default. Google Cloud Infrastructure Manager and
Google-native recipe resources remain roadmap; this module is deliberately AWS
specific.
