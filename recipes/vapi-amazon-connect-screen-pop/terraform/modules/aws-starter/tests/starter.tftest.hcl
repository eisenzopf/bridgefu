mock_provider "aws" {}

variables {
  deployment_id = "support"
  stack_name    = "bridgefu-support"
  template_url  = "https://release.example.test/immutable/template.yaml"
  parameters = {
    ArtifactBucket             = "release-bucket"
    BridgefuImageUri           = "example.test/bridgefu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ConnectInstanceArn         = "arn:aws:connect:us-west-2:123456789012:instance/example"
    LookupArtifactKey          = "release/connect_lookup.zip"
    LookupArtifactVersion      = "v1"
    NestedTemplateBaseUrl      = "https://release.example.test/immutable/cloudformation"
    PrepareArtifactKey         = "release/prepare_handoff.zip"
    PrepareArtifactVersion     = "v1"
    ProvisionerArtifactKey     = "release/vapi_provisioner.zip"
    ProvisionerArtifactVersion = "v1"
    PublicHostedZoneId         = "ZEXAMPLE"
    RuntimeArtifactKey         = "release/starter-runtime.zip"
    RuntimeArtifactSha256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    RuntimeArtifactVersion     = "v1"
    RuntimeProfile             = "Starter"
    SipHostname                = "sip.example.test"
    TargetContactFlowArn       = "arn:aws:connect:us-west-2:123456789012:instance/example/contact-flow/example"
    TransferArtifactKey        = "release/transfer_destination.zip"
    TransferArtifactVersion    = "v1"
    VapiApiKeySecretArn        = "arn:aws:secretsmanager:us-west-2:123456789012:secret:example"
  }
}

run "starter_contract" {
  command = plan

  assert {
    condition     = aws_cloudformation_stack.recipe.parameters["DeploymentId"] == "support"
    error_message = "The module must own the DeploymentId parameter."
  }

  assert {
    condition     = aws_cloudformation_stack.recipe.tags["BridgefuRecipe"] == "vapi-amazon-connect-screen-pop@1"
    error_message = "Recipe ownership tagging drifted."
  }

  assert {
    condition     = contains(aws_cloudformation_stack.recipe.capabilities, "CAPABILITY_NAMED_IAM")
    error_message = "The exact reviewed named-IAM capability is required."
  }
}
