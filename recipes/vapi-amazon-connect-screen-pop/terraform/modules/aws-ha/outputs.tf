output "recipe" {
  description = "Exact recipe identity reported by the canonical CloudFormation application."
  value       = try(aws_cloudformation_stack.recipe.outputs["Recipe"], null)
}

output "support_tier" {
  description = "Evidence-backed support tier; HA remains preview until live failure/load gates pass."
  value       = try(aws_cloudformation_stack.recipe.outputs["SupportTier"], null)
}

output "sip_uri" {
  description = "Public SIP/SIPS transfer URI."
  value       = try(aws_cloudformation_stack.recipe.outputs["SipUri"], null)
}

output "runtime_cluster_name" {
  description = "HA ECS cluster for AWS-native administration."
  value       = try(aws_cloudformation_stack.recipe.outputs["RuntimeClusterName"], null)
}

output "connect_wrapper_flow_arn" {
  description = "Recipe-owned wrapper flow; the customer target flow remains unmodified."
  value       = try(aws_cloudformation_stack.recipe.outputs["ConnectWrapperFlowArn"], null)
}

output "handoff_table_name" {
  description = "AWS-native opaque-correlation context table."
  value       = try(aws_cloudformation_stack.recipe.outputs["HandoffTableName"], null)
}

output "dashboard_url" {
  description = "Primary AWS administrator dashboard."
  value       = try(aws_cloudformation_stack.recipe.outputs["DashboardUrl"], null)
}

output "demo_site_url" {
  description = "Optional nonproduction CloudFront test page URL."
  value       = try(aws_cloudformation_stack.recipe.outputs["DemoSiteUrl"], null)
}
