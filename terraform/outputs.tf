output "public_ip" {
  description = "Elastic IP — the gateway's stable public address (SIP + metrics)."
  value       = aws_eip.this.public_ip
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.this.id
}

output "sip_uri" {
  description = "Point your Vapi SIP transfer/REFER target here."
  value       = "sip:${aws_eip.this.public_ip}:5060"
}

output "healthz_url" {
  description = "Liveness check (reachable from admin_cidr)."
  value       = "http://${aws_eip.this.public_ip}:9090/healthz"
}

output "ssh_command" {
  description = "SSH into the instance (uses the key matching var.public_key)."
  value       = "ssh ec2-user@${aws_eip.this.public_ip}"
}

output "deploy_command" {
  description = "Example deploy.sh invocation (run from the bridgefu repo root)."
  value       = "INSTANCE_IP=${aws_eip.this.public_ip} SSH_KEY=~/.ssh/id_ed25519 CONFIG=./bridgefu.yaml ./deploy.sh"
}
