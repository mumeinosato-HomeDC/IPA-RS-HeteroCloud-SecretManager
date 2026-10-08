#!/usr/bin/env python3
"""Initialize and unseal a single-host OpenBao Raft cluster (lab use).

Unlike bootstrap-openbao.py this does not use per-host systemd credentials or
SSH: it runs `bao operator init` through kubectl exec and writes the unseal
shares and root token to one 0600 JSON file chosen by the operator. Use only
where a single operator machine may legitimately hold every share.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PODS = ('openbao-0', 'openbao-1', 'openbao-2')
ENV = ['env', 'BAO_ADDR=https://127.0.0.1:8200',
       'BAO_CACERT=/openbao/userconfig/openbao-server-tls/ca.crt']


def bao(kubeconfig, pod, *args, data=None, check=True):
    argv = ['kubectl', '--kubeconfig', str(kubeconfig), '-n', 'openbao', 'exec', '-i',
            pod, '-c', 'openbao', '--', *ENV, 'bao', *args]
    result = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError(f'bao {args[0]} {args[1] if len(args) > 1 else ""} failed on {pod}: '
                           f'{result.stderr.strip()[:200]}')
    return result


def status(kubeconfig, pod):
    result = bao(kubeconfig, pod, 'status', '-format=json', check=False)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='0600 JSON file for the unseal shares and root token')
    args = parser.parse_args()
    os.umask(0o077)

    deadline = time.time() + 180
    while not status(args.kubeconfig, PODS[0]):
        if time.time() > deadline:
            raise RuntimeError('openbao-0 never answered')
        time.sleep(3)

    if args.output.exists():
        init = json.loads(args.output.read_text())
    else:
        st = status(args.kubeconfig, PODS[0])
        if st.get('initialized'):
            raise RuntimeError('Cluster is already initialized but no share file exists')
        out = bao(args.kubeconfig, PODS[0], 'operator', 'init', '-key-shares=3',
                  '-key-threshold=2', '-format=json').stdout
        init = json.loads(out)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump({'unseal_keys_b64': init['unseal_keys_b64'],
                       'root_token': init['root_token']}, handle)
    keys = init['unseal_keys_b64']

    for pod in PODS:
        deadline = time.time() + 240
        while True:
            st = status(args.kubeconfig, pod)
            if st.get('initialized') and not st.get('sealed'):
                break
            if st.get('initialized') and st.get('sealed'):
                for key in keys[:2]:
                    bao(args.kubeconfig, pod, 'operator', 'unseal', key, check=False)
            if time.time() > deadline:
                raise RuntimeError(f'{pod} did not unseal')
            time.sleep(4)
    print(json.dumps({'initialized': True, 'unsealed': list(PODS), 'output': str(args.output)}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'lab bootstrap failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
