variable "name" {
  type    = string
  default = "bridgefu"
}
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "autoscaling_group_arn" { type = string }
variable "image" { type = string }
variable "config_host_path" {
  type    = string
  default = "/etc/bridgefu"
}
variable "desired_workers" {
  type    = number
  default = 2
}
variable "sip_port" {
  type    = number
  default = 5060
}
variable "quic_port" {
  type    = number
  default = 4443
}
variable "api_port" {
  type    = number
  default = 9090
}
variable "rtp_port_start" {
  type    = number
  default = 16384
}
variable "rtp_port_end" {
  type    = number
  default = 32767
}
variable "database_name" {
  type    = string
  default = "bridgefu"
}
variable "database_username" {
  type    = string
  default = "bridgefu"
}
variable "database_password" {
  type      = string
  sensitive = true
}
variable "secret_arns" {
  type    = map(string)
  default = {}
}
