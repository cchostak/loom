"""Generate isolated lab configuration and secrets; never alter the default identity registry."""
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.loom/enterprise'
RESOURCE = 'http://localhost:18080'
ISSUER = 'http://localhost:18555'


def write(name, value):
    path = STATE / name
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    path.chmod(0o444)


def jwk():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.private_numbers()
    def encoded(number):
        return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, 'big')).decode().rstrip('=')
    return dict(kty='RSA', use='sig', alg='RS256', kid=secrets.token_hex(16),
                **{k: encoded(v) for k, v in dict(n=n.public_numbers.n, e=n.public_numbers.e,
                    d=n.d, p=n.p, q=n.q, dp=n.dmp1, dq=n.dmq1, qi=n.iqmp).items()})


def provision():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    if (STATE / 'complete').exists():
        return
    if any(STATE.iterdir()):
        raise RuntimeError('Incomplete enterprise provisioning; inspect and archive the lab state before retrying')
    for name in ('state-token', 'audit-token', 'dispatch-key', 'audit-key', 'provider-key'):
        write(name, secrets.token_urlsafe(48))
    scopes = 'model:invoke mcp:connect workspace:read document:read document:write action:propose'
    clients, bindings, credentials = [], [], {}
    for client, tenant, workload in [('researcher', 'alpha', 'strands-researcher'),
                                     ('planner', 'alpha', 'strands-planner'),
                                     ('foreign', 'beta', 'strands-researcher')]:
        secret = secrets.token_urlsafe(48)
        grant = scopes if client != 'planner' else 'model:invoke mcp:connect document:read'
        clients.append(dict(client_id=client, client_secret=secret, grant_types=['client_credentials'],
                            response_types=[], redirect_uris=[], token_endpoint_auth_method='client_secret_basic', scope=grant))
        credentials[client] = dict(secret=secret, scope=grant)
        bindings.append(dict(subject=client, client_id=client, identity=dict(principal='alice',
            workload=workload, tenant=tenant, session='enterprise-' + client, scopes=grant.split())))
    clients.append(dict(client_id='loom-browser', grant_types=['authorization_code'],
        response_types=['code'], redirect_uris=['http://127.0.0.1:18777/callback'],
        token_endpoint_auth_method='none', scope='openid ' + scopes + ' operator:approve'))
    users = []
    for user in ('alice', 'bob'):
        password, salt = secrets.token_urlsafe(24), secrets.token_hex(16)
        users.append(dict(id=user, salt=salt, hash=hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32).hex()))
        credentials[user] = dict(password=password)
        grant = scopes if user == 'alice' else 'operator:approve document:read'
        bindings.append(dict(subject=user, client_id='loom-browser', identity=dict(principal=user,
            workload='enterprise-user', tenant='alpha', session='enterprise-' + user, scopes=grant.split())))
    write('issuer.json', dict(issuer=ISSUER, resource=RESOURCE, clients=clients, users=users,
                            jwks=dict(keys=[jwk()]), cookieKeys=[secrets.token_hex(32)]))
    write('credentials.json', credentials)
    write('edge.json', dict(resource=RESOURCE, oidc=dict(issuer=ISSUER, audience=RESOURCE,
        discovery_url='http://issuer:8080/.well-known/openid-configuration',
        jwks_url='http://issuer:8080/jwks', public_jwks_url=ISSUER + '/jwks', bindings=bindings),
        state_url='http://state:8080', audit_url='http://audit:8080',
        state_token_file='/run/secrets/state-token', audit_token_file='/run/secrets/audit-token',
        dispatch_key_file='/run/secrets/dispatch-key'))
    gateway = yaml.safe_load((ROOT / 'config/agentgateway-config.yaml').read_text())
    remote = dict(host='state:8081', domain='loom-enterprise', failureMode='failClosed',
                  descriptors=[dict(entries=[dict(key='dispatch', value='default(request.headers["x-loom-dispatch"], "missing")')])])
    gateway['llm']['policies'] = dict(remoteRateLimit=remote)
    gateway['mcp']['policies']['remoteRateLimit'] = remote
    for model in gateway['llm']['models']:
        model['provider'] = 'openai'
        model['params'] = dict(baseUrl='http://connector:8080/v1', apiKey='connector-holds-provider-key')
        model['requestHeaders'] = dict(set={'x-loom-dispatch': 'request.headers["x-loom-dispatch"]'})
    write('gateway.yaml', yaml.safe_dump(gateway))
    policy = json.loads((ROOT / 'config/policy.json').read_text())
    # Preserve production rules; add explicit enterprise identity variants.
    rules = []
    for rule in policy['rules']:
        if rule.get('workload', '').startswith('strands-'):
            for tenant in ('alpha', 'beta'):
                copy = dict(rule, id='enterprise-' + tenant + '-' + rule['id'],
                            principal='alice', tenant=tenant)
                rules.append(copy)
            if rule['workload'] == 'strands-researcher':
                rules.append(dict(rule, id='enterprise-user-' + rule['id'], principal='alice',
                                  tenant='alpha', workload='enterprise-user'))
    policy['rules'] += rules
    write('policy.json', policy)
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture-provider')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('fixture-provider')]), critical=False)
            .sign(cert_key, hashes.SHA256()))
    write('fixture.crt', cert.public_bytes(serialization.Encoding.PEM).decode())
    write('fixture.key', cert_key.private_bytes(serialization.Encoding.PEM,
          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    (STATE / 'workspace').mkdir()
    write('workspace/evidence.txt', 'Untrusted enterprise lab evidence.\n')
    write('complete', 'enterprise lab provisioned\n')


if __name__ == '__main__':
    provision()
