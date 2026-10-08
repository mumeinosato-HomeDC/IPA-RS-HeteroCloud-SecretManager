#!/usr/bin/env python3
"""Reconcile OIDC, personal KV and snapshot-only Kubernetes authentication.

The Keycloak client JSON is read from stdin. Neither it nor the decrypted
initial root token is written to disk, passed in argv, or printed.
"""

import argparse
import base64
import getpass
import http.client
import json
import os
from pathlib import Path
import resource
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse


PODS = ('openbao-0', 'openbao-1', 'openbao-2')


def command(argv, data=None):
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=False, timeout=30)
    if p.returncode:
        raise RuntimeError(f'{argv[0]} failed')
    return p.stdout


class Forward:
    def __init__(self, kubeconfig, pod, port, target_port=8200):
        self.kubeconfig, self.pod, self.port = kubeconfig, pod, port
        self.target_port = target_port

    def __enter__(self):
        self.proc = subprocess.Popen([
            'kubectl', '--kubeconfig', str(self.kubeconfig), '-n', 'openbao',
            'port-forward', f'pod/{self.pod}', f'{self.port}:{self.target_port}',
            '--address', '127.0.0.1'], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        for _ in range(40):
            if self.proc.poll() is not None:
                raise RuntimeError('port-forward exited')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.2):
                    return self
            except OSError:
                time.sleep(.25)
        raise RuntimeError('port-forward timed out')

    def __exit__(self, *_):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class TLSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, port, context):
        super().__init__(hostname, 8200, context=context, timeout=20)
        self.local_port = port

    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.local_port), timeout=20)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class API:
    def __init__(self, pod, port, ca, token):
        self.host = f'{pod}.openbao-internal.openbao.svc.cluster.local'
        self.port = port
        self.context = ssl.create_default_context(cafile=str(ca))
        self.token = token

    def request(self, method, path, body=None, allow=(200, 204)):
        conn = TLSConnection(self.host, self.port, self.context)
        headers = {'X-Vault-Token': self.token}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body, separators=(',', ':')).encode()
        try:
            conn.request(method, '/v1/' + path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            if response.status not in allow:
                # Do not include server body: some API errors can echo input.
                raise RuntimeError(f'OpenBao {method} {path} returned HTTP {response.status}')
            return json.loads(data) if data else {}
        finally:
            conn.close()


def ensure_auth(api, path, auth_type):
    mounts = api.request('GET', 'sys/auth')['data']
    if path + '/' not in mounts:
        api.request('POST', 'sys/auth/' + path, {'type': auth_type}, (200, 204))
    else:
        assert mounts[path + '/']['type'] == auth_type


def ensure_kv(api):
    mounts = api.request('GET', 'sys/mounts')['data']
    if 'secret/' not in mounts:
        api.request('POST', 'sys/mounts/secret',
                    {'type': 'kv', 'options': {'version': '2'}}, (200, 204))
    else:
        assert mounts['secret/']['type'] == 'kv'
        assert mounts['secret/']['options']['version'] == '2'


def ensure_restore_auth(api):
    api.request('PUT', 'sys/policies/acl/heterosecrets-restore-probe', {'policy': '''
path "secret/data/system/restore-probe" { capabilities = ["read"] }
path "auth/oidc/role/users" { capabilities = ["read"] }
'''})
    ensure_auth(api, 'kubernetes', 'kubernetes')
    api.request('POST', 'auth/kubernetes/role/heterosecrets-restore-probe', {
        'bound_service_account_names': ['openbao'],
        'bound_service_account_namespaces': ['openbao'],
        'token_policies': ['heterosecrets-restore-probe'],
        'token_ttl': '5m', 'token_max_ttl': '5m',
    })


def ensure_flash_auth(api):
    """Bind each Flash service account to only its own KV v2 subtree."""
    ensure_kv(api)
    ensure_auth(api, 'kubernetes', 'kubernetes')
    auth = api.request('GET', 'sys/auth')['data']['kubernetes/']
    accessor = auth['accessor']
    assert accessor.startswith('auth_kubernetes_')
    api.request('PUT', 'sys/policies/acl/heterosecrets-flash-workload', {
        'policy': f'''
path "secret/data/flash/{{{{identity.entity.aliases.{accessor}.metadata.service_account_name}}}}/*" {{
  capabilities = ["read"]
}}
'''
    })
    api.request('POST', 'auth/kubernetes/role/heterosecrets-flash-workload', {
        'bound_service_account_names': ['*'],
        'bound_service_account_namespaces': ['heterocloud-flash-workloads'],
        'token_policies': ['heterosecrets-flash-workload'],
        'token_ttl': '15m', 'token_max_ttl': '1h',
    })
    api.request('PUT', 'sys/policies/acl/heterosecrets-flash-api', {
        'policy': '''
path "secret/data/flash/*" { capabilities = ["create", "update"] }
path "secret/metadata/flash/*" { capabilities = ["read", "list", "delete"] }
'''
    })
    api.request('POST', 'auth/kubernetes/role/heterosecrets-flash-api', {
        'bound_service_account_names': ['heterocloud-heterocloud'],
        'bound_service_account_namespaces': ['heterocloud'],
        'token_policies': ['heterosecrets-flash-api'],
        'token_ttl': '15m', 'token_max_ttl': '1h',
    })


def verify_oidc_auth_url(api, role, origin):
    """Reject an OIDC role that returns HTTP 200 without a usable login URL."""
    redirect = origin + '/ui/vault/auth/oidc/oidc/callback'
    response = api.request('POST', 'auth/oidc/oidc/auth_url', {
        'role': role, 'redirect_uri': redirect,
    })
    auth_url = (response.get('data') or {}).get('auth_url')
    if not auth_url:
        raise RuntimeError(f'OIDC role {role} has no auth_url for {origin}')
    parsed = urlparse(auth_url)
    if parsed.scheme != 'https' or parse_qs(parsed.query).get('redirect_uri') != [redirect]:
        raise RuntimeError(f'OIDC role {role} returned an invalid auth_url for {origin}')


def configure(api, config, origin, legacy_origin=None):
    parsed = urlparse(origin)
    assert parsed.scheme in ('http', 'https') and parsed.netloc and not parsed.path
    if parsed.scheme == 'http':
        assert parsed.hostname and parsed.hostname.endswith('.heteronetwork.internal')
    if legacy_origin:
        legacy = urlparse(legacy_origin)
        assert legacy.scheme == 'https' and legacy.netloc and not legacy.path
    issuer = config['issuer']
    assert issuer.startswith('https://') and '/realms/' in issuer
    assert config['client_id'] and config['client_secret'] and config['owner_subject']
    callback = origin + '/v1/auth/oidc/callback'
    ui_callback = origin + '/ui/vault/auth/oidc/oidc/callback'
    cli_callback = 'http://localhost:8250/oidc/callback'
    redirects = [callback, ui_callback, cli_callback]
    if legacy_origin:
        redirects.extend([
            legacy_origin + '/v1/auth/oidc/callback',
            legacy_origin + '/ui/vault/auth/oidc/oidc/callback',
        ])

    ensure_kv(api)
    api.request('PUT', 'sys/policies/acl/heterosecrets-user', {'policy': '''
path "secret/data/users/{{identity.entity.id}}/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/users/{{identity.entity.id}}" {
  capabilities = ["list"]
}
path "secret/metadata/users/{{identity.entity.id}}/*" {
  capabilities = ["read", "list", "delete"]
}
'''})
    api.request('PUT', 'sys/policies/acl/heterosecrets-owner', {'policy': '''
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
'''})
    api.request('PUT', 'sys/policies/acl/heterosecrets-snapshot', {'policy': '''
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
'''})

    ensure_auth(api, 'oidc', 'oidc')
    oidc_config = {
        'oidc_discovery_url': issuer,
        'oidc_client_id': config['client_id'],
        'oidc_client_secret': config['client_secret'],
        'default_role': 'users',
    }
    if config.get('oidc_discovery_ca_pem'):
        # Private-CA identity providers (e.g. an internal Keycloak).
        oidc_config['oidc_discovery_ca_pem'] = config['oidc_discovery_ca_pem']
    api.request('POST', 'auth/oidc/config', oidc_config)
    api.request('POST', 'auth/oidc/role/users', {
        'role_type': 'oidc', 'user_claim': 'sub',
        'oidc_scopes': ['openid', 'profile', 'email'],
        'allowed_redirect_uris': redirects,
        'token_policies': ['default', 'heterosecrets-user'],
        'token_ttl': '30m', 'token_max_ttl': '8h',
    })
    api.request('POST', 'auth/oidc/role/owner', {
        'role_type': 'oidc', 'user_claim': 'sub',
        'oidc_scopes': ['openid', 'profile', 'email'],
        'allowed_redirect_uris': redirects,
        'bound_claims': {'sub': config['owner_subject']},
        'token_policies': ['default', 'heterosecrets-owner'],
        'token_ttl': '15m', 'token_max_ttl': '1h',
    })

    ensure_auth(api, 'kubernetes', 'kubernetes')
    api.request('POST', 'auth/kubernetes/config', {
        'kubernetes_host': 'https://kubernetes.default.svc:443',
    })
    api.request('POST', 'auth/kubernetes/role/heterosecrets-snapshot', {
        'bound_service_account_names': ['openbao-snapshot'],
        'bound_service_account_namespaces': ['openbao'],
        'token_policies': ['heterosecrets-snapshot'],
        'token_ttl': '15m', 'token_max_ttl': '15m',
    })
    ensure_restore_auth(api)
    ensure_flash_auth(api)

    mounts = api.request('GET', 'sys/auth')['data']
    assert mounts['oidc/']['type'] == 'oidc'
    assert mounts['kubernetes/']['type'] == 'kubernetes'
    owner = api.request('GET', 'auth/oidc/role/owner')['data']
    assert owner['bound_claims']['sub'] == config['owner_subject']
    user = api.request('GET', 'auth/oidc/role/users')['data']
    assert 'heterosecrets-user' in user.get('token_policies', user.get('policies', []))
    for candidate_origin in (origin, legacy_origin):
        if candidate_origin:
            for role in ('owner', 'users'):
                verify_oidc_auth_url(api, role, candidate_origin)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--ssh-key', type=Path,
                        help='Age identity fallback for the init artifact (unused with an owner/admin token)')
    parser.add_argument('--recovery-identity', type=Path,
                        help='Dedicated age identity for the encrypted init artifact')
    parser.add_argument('--recovery-dir', type=Path,
                        help='Directory holding openbao-init.json.age (not needed with an admin token)')
    parser.add_argument('--public-origin', required=True)
    parser.add_argument('--legacy-origin')
    parser.add_argument('--restore-auth-only', action='store_true',
                        help='Reconcile only the read-only isolated-restore identity')
    parser.add_argument('--flash-auth-only', action='store_true',
                        help='Reconcile only Flash workload and HeteroCloud API identities')
    parser.add_argument('--prompt-admin-token', action='store_true',
                        help='Read a short-lived owner token from the terminal')
    parser.add_argument('--admin-token-stdin', action='store_true',
                        help='Read a short-lived owner token from stdin for one-shot operator handoff')
    parser.add_argument('--port', type=int, default=18420)
    args = parser.parse_args()
    if args.prompt_admin_token and args.admin_token_stdin:
        parser.error('choose only one owner token input method')
    if args.admin_token_stdin and not (args.flash_auth_only or args.restore_auth_only):
        parser.error('--admin-token-stdin requires a scoped auth operation')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    config = None if args.restore_auth_only or args.flash_auth_only else json.load(sys.stdin)
    encrypted = args.recovery_dir / 'openbao-init.json.age' if args.recovery_dir else None
    if args.admin_token_stdin:
        admin_token = sys.stdin.readline().rstrip('\r\n')
        if not admin_token:
            raise RuntimeError('OpenBao owner token is required')
    else:
        admin_token = getpass.getpass('OpenBao owner token: ') if args.prompt_admin_token else None
    if config is not None:
        admin_token = admin_token or config.pop('admin_token', None)
    if not admin_token:
        if encrypted is None or not (args.recovery_identity or args.ssh_key):
            raise RuntimeError('OpenBao admin token, or --recovery-dir with an age identity, is required')
        admin_token = json.loads(command(['age', '-d', '-i',
                                          str(args.recovery_identity or args.ssh_key),
                                          str(encrypted)]))['root_token']
    ca_b64 = command(['kubectl', '--kubeconfig', str(args.kubeconfig), '-n', 'openbao',
                      'get', 'secret', 'openbao-server-tls', '-o', 'jsonpath={.data.ca\\.crt}'])
    with tempfile.TemporaryDirectory(prefix='heterosecrets-config-', dir='/dev/shm') as tmp:
        ca = Path(tmp) / 'ca.crt'
        ca.write_bytes(base64.b64decode(ca_b64))
        context = ssl.create_default_context(cafile=str(ca))
        active = None
        for pod in PODS:
            with Forward(args.kubeconfig, pod, args.port):
                conn = TLSConnection(f'{pod}.openbao-internal.openbao.svc.cluster.local',
                                     args.port, context)
                try:
                    conn.request('GET', '/v1/sys/leader')
                    reply = conn.getresponse()
                    if reply.status == 200 and json.load(reply)['is_self']:
                        active = pod
                        break
                finally:
                    conn.close()
        if active is None:
            raise RuntimeError('No active OpenBao leader')
        with Forward(args.kubeconfig, active, args.port):
            api = API(active, args.port, ca, admin_token)
            if args.restore_auth_only:
                ensure_restore_auth(api)
            elif args.flash_auth_only:
                ensure_flash_auth(api)
            else:
                configure(api, config, args.public_origin, args.legacy_origin)
    if args.flash_auth_only:
        print(json.dumps({'flash_auth_configured': True, 'leader': active}))
    elif args.restore_auth_only:
        print(json.dumps({'restore_auth_configured': True, 'leader': active}))
    else:
        print(json.dumps({'configured': True, 'leader': active,
                          'oidc_client_id': config['client_id'],
                          'owner_subject_verified': True,
                          'snapshot_auth': 'kubernetes-service-account'}))


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, KeyError, RuntimeError, OSError, ValueError) as exc:
        print(f'configuration failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
