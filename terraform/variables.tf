variable "region" {
  description = "AWS region to deploy into. Should match aws.region in bridgefu.yaml and your Amazon Connect instance's region."
  type        = string
  default     = "us-west-2"
}

variable "name" {
  description = "Name prefix/tag applied to all resources."
  type        = string
  default     = "bridgefu"
}

variable "instance_type" {
  description = <<-EOT
    EC2 instance type (arm64/Graviton). Default t4g.2xlarge (8 vCPU, 32 GB) gives
    good parallelism for the first cold build of the full rvoip tree. Subsequent
    deploys only recompile bridgefu (the rvoip layers cache). Resize down later
    (e.g. t4g.medium) if you only need to keep the gateway running.
  EOT
  type        = string
  default     = "t4g.2xlarge"
}

variable "root_volume_gb" {
  description = "Root EBS volume size in GB. Needs headroom for the Rust build (target/) + Docker images."
  type        = number
  default     = 30
}

variable "public_key" {
  description = "SSH public key material (contents of e.g. ~/.ssh/id_ed25519.pub) used to create the EC2 key pair for SSH + deploy.sh."
  type        = string
}

variable "admin_cidr" {
  description = "CIDR allowed to reach SSH (22) and the metrics/health HTTP port (9090). Lock this to your own IP, e.g. \"203.0.113.4/32\"."
  type        = string
}

variable "sip_cidr" {
  description = <<-EOT
    CIDR allowed to reach SIP (5060 udp/tcp) and RTP (16384-32767 udp).
    Defaults open (0.0.0.0/0) for the POC test. TODO: lock to Vapi/carrier CIDRs
    once known (see PRD §6 / §10).
  EOT
  type        = string
  default     = "0.0.0.0/0"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the public subnet."
  type        = string
  default     = "10.42.1.0/24"
}
