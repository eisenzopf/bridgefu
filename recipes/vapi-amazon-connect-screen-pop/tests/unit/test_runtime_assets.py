from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


RECIPE = Path(__file__).resolve().parents[2]
RUNTIME = RECIPE / "runtime"


class RuntimeAssetTests(unittest.TestCase):
    def render(self, security: str):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in (
            "etc/bridgefu",
            "etc/haproxy",
            "opt/aws/amazon-cloudwatch-agent/var",
            "opt/aws/amazon-cloudwatch-agent/etc",
        ):
            (root / relative).mkdir(parents=True)
        environment = {
            **os.environ,
            "BRIDGEFU_RENDER_ROOT": str(root),
            "BRIDGEFU_DEPLOYMENT_ID": "bf-test",
            "AWS_REGION": "us-west-2",
            "BRIDGEFU_SIP_HOSTNAME": (
                "203.0.113.10" if security == "sip_rtp" else "sip.example.com"
            ),
            "BRIDGEFU_CONTROL_HOSTNAME": "control.sip.example.com",
            "BRIDGEFU_PUBLIC_IP": "203.0.113.10",
            "BRIDGEFU_PRIVATE_IP": "10.42.0.10",
            "CONNECT_INSTANCE_ARN": "arn:aws:connect:us-west-2:123456789012:instance/11111111-1111-1111-1111-111111111111",
            "CONNECT_ENTRY_FLOW_ID": "22222222-2222-2222-2222-222222222222",
            "BRIDGEFU_SIP_SECURITY": security,
            "BRIDGEFU_MAX_CONCURRENT_CALLS": "100",
            "VAPI_SIGNALING_CIDRS": "44.229.228.186/32,44.238.177.138/32",
            "BRIDGEFU_RUNTIME_LOG_GROUP": "/bridgefu/bf-test/runtime",
            "BRIDGEFU_PROMETHEUS_LOG_GROUP": "/bridgefu/bf-test/prometheus",
        }
        subprocess.run(
            [sys.executable, str(RUNTIME / "render.py")],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return temporary, root

    def test_secure_and_compatibility_configs_are_minimal_and_exact(self):
        for security, edge_key, port in (
            ("sips_srtp", "sip_tls", 5061),
            ("sip_rtp", "sip_rtp", 5060),
        ):
            with self.subTest(security=security):
                temporary, root = self.render(security)
                try:
                    config = yaml.safe_load(
                        (root / "etc/bridgefu/bridgefu.yaml").read_text()
                    )
                    self.assertEqual(config["recipes"]["support"]["with"]["sip_security"], security)
                    self.assertEqual(
                        config["edge"]["public_host"],
                        "203.0.113.10" if security == "sip_rtp" else "sip.example.com",
                    )
                    self.assertEqual(config["edge"][edge_key]["bind"], f"0.0.0.0:{port}")
                    self.assertEqual(config["observability"]["http_bind"], "127.0.0.1:9090")
                    self.assertEqual(config["persistence"]["backend"], "sqlite")
                    self.assertNotIn("legacy_vapi_connect", config)
                    agent = json.loads(
                        (root / "opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json").read_text()
                    )
                    selectors = json.dumps(agent["logs"]["metrics_collected"])
                    self.assertIn("bridgefu_process_ready", selectors)
                    self.assertIn("bridgefu_gateway_native_active_routes", selectors)
                    self.assertNotIn("bridgefu_active_sessions", selectors)
                    self.assertNotIn("correlation_id", selectors)
                finally:
                    temporary.cleanup()

    def test_host_service_is_non_root_read_only_and_capability_free(self):
        service = (RUNTIME / "bridgefu.service").read_text()
        for required in (
            "--read-only",
            "--user 65532:65532",
            "--cap-drop ALL",
            "no-new-privileges:true",
            "--network host",
            "--stop-timeout 60",
        ):
            self.assertIn(required, service)
        self.assertNotIn("/var/run/docker.sock", service)
        self.assertNotIn("--privileged", service)

    def render_ha(self, role: str, security: str = "sips_srtp"):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        environment = {
            **os.environ,
            "BRIDGEFU_RENDER_ROOT": str(root),
            "BRIDGEFU_DEPLOYMENT_ID": "bf-ha-test",
            "BRIDGEFU_ROLE": role,
            "BRIDGEFU_SLOT": f"{role}-a",
            "AWS_REGION": "us-west-2",
            "BRIDGEFU_SIP_HOSTNAME": "sip.example.com",
            "BRIDGEFU_UCTP_HOSTNAME": "uctp.sip.example.com",
            "BRIDGEFU_PUBLIC_IP": "203.0.113.10",
            "CONNECT_INSTANCE_ARN": "arn:aws:connect:us-west-2:123456789012:instance/11111111-1111-1111-1111-111111111111",
            "CONNECT_ENTRY_FLOW_ID": "22222222-2222-2222-2222-222222222222",
            "BRIDGEFU_SIP_SECURITY": security,
            "BRIDGEFU_MAX_CONCURRENT_CALLS": "100",
            "VAPI_SIGNALING_CIDRS": "44.229.228.186/32,44.238.177.138/32",
        }
        if role == "gateway":
            environment.update(
                {
                    "BRIDGEFU_GATEWAY_ID": "gateway-a",
                    "BRIDGEFU_WORKER_TARGETS_JSON": json.dumps(
                        [
                            {
                                "worker_id": "00000000-0000-4000-8000-000000000011",
                                "endpoint": "worker.sip.example.com:9443",
                                "server_name": "worker.sip.example.com",
                            },
                            {
                                "worker_id": "00000000-0000-4000-8000-000000000012",
                                "endpoint": "worker.sip.example.com:9444",
                                "server_name": "worker.sip.example.com",
                            },
                        ]
                    ),
                }
            )
        else:
            environment["BRIDGEFU_WORKER_ID"] = (
                "00000000-0000-4000-8000-000000000011"
            )
        subprocess.run(
            [sys.executable, str(RUNTIME / "render-ha.py")],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return temporary, root

    def test_ha_gateway_and_worker_are_role_separated_with_shared_catalog_inputs(self):
        rendered = {}
        for role in ("gateway", "worker"):
            temporary, root = self.render_ha(role)
            try:
                config = yaml.safe_load(
                    (root / "etc/bridgefu/bridgefu.yaml").read_text()
                )
                rendered[role] = config
                self.assertEqual(config["runtime"]["mode"], role)
                self.assertEqual(config["persistence"]["backend"], "postgres")
                self.assertEqual(config["persistence"]["redis_clustered"], True)
                self.assertEqual(
                    config["persistence"]["worker_capabilities"], ["amazon_connect"]
                )
                self.assertEqual(
                    config["recipes"]["support"]["with"]["connect_entry_contact_flow_id"],
                    "22222222-2222-2222-2222-222222222222",
                )
                agent = json.loads(
                    (
                        root
                        / "opt/aws/amazon-cloudwatch-agent/etc/bridgefu.json"
                    ).read_text()
                )
                selectors = json.dumps(agent["logs"]["metrics_collected"])
                self.assertIn("bridgefu_private_forwarding_active_routes", selectors)
                self.assertNotIn("correlation_id", selectors)
            finally:
                temporary.cleanup()
        self.assertTrue(rendered["gateway"]["api"]["enabled"])
        self.assertFalse(rendered["worker"]["api"]["enabled"])
        self.assertIn("gateway", rendered["gateway"]["private_forwarding"])
        self.assertIn("worker", rendered["worker"]["private_forwarding"])
        self.assertEqual(
            rendered["gateway"]["recipes"], rendered["worker"]["recipes"]
        )

    def test_ha_secret_url_and_tls_contract_is_bounded(self):
        path = RUNTIME / "bridgefu-ha-load-secrets.py"
        spec = importlib.util.spec_from_file_location("bridgefu_ha_secrets", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        url = module.database_url(
            json.dumps(
                {
                    "username": "bridgefu",
                    "password": "p@ss:/word",
                    "host": "db.internal",
                    "port": 5432,
                    "dbname": "bridgefu",
                }
            )
        )
        self.assertEqual(
            url,
            "postgres://bridgefu:p%40ss%3A%2Fword@db.internal:5432/bridgefu?sslmode=require",
        )
        bundle = {
            "ca_crt": "CA\n",
            "gateway_crt": "GATEWAY CERT\n",
            "gateway_key": "GATEWAY KEY\n",
            "worker_crt": "WORKER CERT\n",
            "worker_key": "WORKER KEY\n",
        }
        self.assertEqual(
            module.tls_bundle(json.dumps(bundle), "gateway"),
            ("CA\n", "GATEWAY CERT\n", "GATEWAY KEY\n"),
        )

    def test_ha_bootstrap_uses_ecs_host_network_security_and_idle_rotation(self):
        bootstrap = (RUNTIME / "ha-host-bootstrap.sh").read_text()
        self.assertNotIn("sshd", bootstrap)
        self.assertIn("ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true", bootstrap)
        refresh = (RUNTIME / "bridgefu-ha-cert-refresh").read_text()
        self.assertIn("BRIDGEFU_UCTP_HOSTNAME", refresh)
        reload_script = (RUNTIME / "bridgefu-ha-cert-reload").read_text()
        self.assertIn("bridgefu_gateway_native_active_routes", reload_script)
        self.assertIn("aws ecs stop-task", reload_script)
        protection = (RUNTIME / "bridgefu-ha-scale-protection").read_text()
        self.assertIn("bridgefu_gateway_native_active_routes", protection)
        self.assertIn("bridgefu_private_egress_active_routes", protection)
        self.assertIn("bridgefu_amazon_durable_cleanups_pending", protection)
        self.assertNotIn("bridgefu_cleanup_pending", protection)
        self.assertIn("protected=true", protection)
        self.assertIn("set-instance-protection", protection)
        ha_agent = json.loads((RUNTIME / "cloudwatch-agent-ha.json.tmpl").read_text())
        emf = ha_agent["logs"]["metrics_collected"]["prometheus"]["emf_processor"]
        self.assertEqual(emf["metric_namespace"], "Bridgefu/Runtime")
        selectors = json.dumps(emf["metric_declaration"])
        self.assertIn("bridgefu_private_egress_active_routes", selectors)
        self.assertIn("bridgefu_amazon_durable_cleanups_pending", selectors)
        self.assertNotIn("bridgefu_cleanup_pending", selectors)

    def test_bootstrap_has_no_ssh_and_pins_every_download(self):
        bootstrap = (RUNTIME / "bootstrap.sh").read_text()
        self.assertNotIn("sshd", bootstrap)
        self.assertNotIn("authorized_keys", bootstrap)
        self.assertIn("set -a\nsource /etc/bridgefu/runtime.conf\nset +a", bootstrap)
        self.assertIn("BRIDGEFU_BOOTSTRAP_STATUS_FILE", bootstrap)
        self.assertIn("record_step bridgefu-service-start", bootstrap)
        self.assertIn(
            "record_step control-readiness\n"
            "control_ready=false\n"
            "for _ in $(seq 1 30); do",
            bootstrap,
        )
        self.assertIn('if [[ "$control_ready" != true ]]; then', bootstrap)
        starter_template = (
            RECIPE / "cloudformation/nested/runtime-starter.yaml"
        ).read_text()
        self.assertIn("bootstrap failed during %s", starter_template)
        self.assertIn("^[a-z0-9-]{1,64}$", starter_template)
        pull = (RUNTIME / "bridgefu-pull-image").read_text()
        self.assertIn("@sha256:", pull)
        self.assertIn("mktemp -d /run/bridgefu/docker-config.", pull)
        self.assertIn('export DOCKER_CONFIG="$docker_config"', pull)
        self.assertNotIn("/root/.docker", pull)
        self.assertIn("journalctl --no-pager", bootstrap)
        refresh = (RUNTIME / "bridgefu-cert-refresh").read_text()
        self.assertNotIn("set -x", refresh)
        self.assertIn("certificate-reload-pending", refresh)
        reload_script = (RUNTIME / "bridgefu-cert-reload").read_text()
        self.assertIn("bridgefu_gateway_native_active_routes", reload_script)
        self.assertIn("bridgefu_amazon_durable_cleanups_pending", reload_script)
        self.assertNotIn("bridgefu_active_sessions", reload_script)
        self.assertIn('active == 0', reload_script)


if __name__ == "__main__":
    unittest.main()
