#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

terraform fmt -check -recursive "$root/deploy/terraform"

# Every implemented public gateway surface must remain connected to its
# cloud listener/firewall. Operations health and metrics stay isolated below.
for required in \
  'resource "aws_lb_listener" "gateway_api"' \
  'resource "aws_lb_target_group" "gateway_api"' \
  'resource "aws_lb_listener" "gateway_quic"' \
  'resource "aws_lb_listener" "gateway_sip"' \
  'resource "aws_lb_listener" "gateway_webrtc_ws"' \
  'resource "aws_lb_listener" "gateway_webrtc_whip"' \
  'resource "aws_eip_association" "gateway_media"'; do
  if ! grep -Fq "$required" "$root/deploy/terraform/aws/networking.tf"; then
    echo "required AWS split-gateway surface is missing: $required" >&2
    exit 1
  fi
done
for required in \
  'resource "google_compute_forwarding_rule" "gateway_api"' \
  'resource "google_compute_firewall" "gateway_api"' \
  'resource "google_compute_forwarding_rule" "gateway_quic"' \
  'resource "google_compute_firewall" "gateway_sip"' \
  'resource "google_compute_firewall" "gateway_rtp"' \
  'resource "google_compute_firewall" "gateway_webrtc_signaling"' \
  'resource "google_compute_firewall" "gateway_webrtc_media"'; do
  if ! grep -Fq "$required" "$root/deploy/terraform/gcp/networking.tf"; then
    echo "required GCP split-gateway surface is missing: $required" >&2
    exit 1
  fi
done

if grep -En \
  'prometheus.io/port"[[:space:]]*=[[:space:]]*tostring\(var\.api_port\)|/readyz[^\n]*var\.api_port|/metrics[^\n]*var\.api_port' \
  "$root/deploy/terraform/aws/main.tf" \
  "$root/deploy/terraform/gcp/kubernetes.tf"; then
  echo "operations route was attached to the public gateway API port" >&2
  exit 1
fi
for file in \
  "$root/deploy/terraform/aws/variables.tf" \
  "$root/deploy/terraform/gcp/variables.tf"; do
  if ! grep -Fq 'variable "operations_port"' "$file"; then
    echo "dedicated operations port is missing from $file" >&2
    exit 1
  fi
done

for cloud in aws gcp; do
  terraform -chdir="$root/deploy/terraform/$cloud" init -backend=false -input=false
  terraform -chdir="$root/deploy/terraform/$cloud" validate
done
