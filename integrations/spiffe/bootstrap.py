"""Bootstrap the local trust domain through SPIRE's host-only admin socket."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.loom/spiffe'
COMPOSE = ['docker', 'compose', '-p', 'loom-enterprise', '-f', 'docker-compose.yml',
           '-f', 'integrations/enterprise/compose.yml', '-f', 'integrations/spiffe/compose.bootstrap.yml']
PARENT = 'spiffe://loom.local/agent/loom'


def admin(*args):
    result = subprocess.run(COMPOSE + ['exec', '-T', 'spire-server', '/opt/spire/bin/spire-server',
                            *args, '-socketPath', '/run/spire-server/api.sock'],
                            cwd=ROOT, check=True, capture_output=True)
    return result.stdout.decode()


def provision():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    if not (STATE / 'agent.conf').exists():
        token = json.loads(admin('token', 'generate', '-spiffeID', PARENT, '-output', 'json'))['value']
        (STATE / 'bundle.pem').write_text(admin('bundle', 'show', '-format', 'pem'))
        (STATE / 'agent.conf').write_text('''agent {
  data_dir = "/data"
  server_address = "spire-server"
  server_port = "8081"
  socket_path = "/run/spire/agent.sock"
  trust_domain = "loom.local"
  trust_bundle_path = "/config/bundle.pem"
  log_level = "WARN"
  join_token = "''' + token + '''"
}
plugins {
  KeyManager "disk" { plugin_data { directory = "/data/keys" } }
  NodeAttestor "join_token" { plugin_data {} }
  WorkloadAttestor "docker" { plugin_data { docker_socket_path = "unix:///relay/docker.sock" } }
}
''')
        (STATE / 'agent.conf').chmod(0o600)
    entries = json.loads(admin('entry', 'show', '-output', 'json')).get('entries', [])
    existing = {e['spiffe_id']['path'] for e in entries}
    services = ['control-plane', 'control-plane-b', 'guardrail-proxy', 'state', 'audit',
                'connector', 'normalizer', 'lab-ingress', 'agentgateway',
                'issuer-mtls', 'presidio-mtls', 'squid-mtls', 'collector-mtls', 'jaeger-mtls',
                'connector-egress', 'identity-probe']
    services += ['strands-' + role for role in ('researcher', 'planner', 'operator', 'publisher')]
    for service in services:
        path = '/workload/' + service
        if path in existing:
            continue
        admin('entry', 'create', '-parentID', PARENT, '-spiffeID', 'spiffe://loom.local' + path,
              '-x509SVIDTTL', '300', '-selector', 'docker:label:com.docker.compose.project:loom-enterprise',
              '-selector', 'docker:label:com.docker.compose.service:' + service)


if __name__ == '__main__':
    provision()
