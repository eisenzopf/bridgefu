output "recipe" {
  description = "Exact recipe identity reported by the canonical CloudFormation application."
  value       = try(aws_cloudformation_stack.recipe.outputs["Recipe"], null)
}

output "support_tier" {
  description = "Evidence-backed support tier reported by the deployed revision."
  value       = try(aws_cloudformation_stack.recipe.outputs["SupportTier"], null)
}

output "sip_uri" {
  description = "Public SIP/SIPS transfer URI."
  value       = try(aws_cloudformation_stack.recipe.outputs["SipUri"], null)
}

output "connect_wrapper_flow_arn" {
  description = "Recipe-owned wrapper flow; the customer target flow remains unmodified."
  value       = try(aws_cloudformation_stack.recipe.outputs["ConnectWrapperFlowArn"], null)
}

output "connect_agent_guide_flow_arn" {
  description = "Recipe-owned Agent Workspace guide flow."
  value       = try(aws_cloudformation_stack.recipe.outputs["ConnectAgentGuideFlowArn"], null)
}

output "handoff_table_name" {
  description = "AWS-native opaque-correlation context table."
  value       = try(aws_cloudformation_stack.recipe.outputs["HandoffTableName"], null)
}

output "runtime_instance_id" {
  description = "Starter runtime instance for SSM and operational checks."
  value       = try(aws_cloudformation_stack.recipe.outputs["RuntimeInstanceId"], null)
}

output "dashboard_url" {
  description = "Primary AWS administrator dashboard."
  value       = try(aws_cloudformation_stack.recipe.outputs["DashboardUrl"], null)
}

output "demo_site_url" {
  description = "Optional nonproduction CloudFront test page URL."
  value       = try(aws_cloudformation_stack.recipe.outputs["DemoSiteUrl"], null)
}
