# Single-host lab deployment

This fork adds switches so the chart and scripts run outside HeteroNetwork
(k3s, one host, private CA, an existing Envoy Gateway). Upstream defaults are
unchanged: `python3 scripts/verify-chart.py` still passes.

1. Create the `openbao` namespace with the restricted Pod Security labels
   (`namespace.create=false` in `values-lab.yaml`).
2. Create Secret `openbao-server-tls` (`tls.crt`, `tls.key`, `ca.crt`) with the SANs
   from `templates/pki.yaml`, and ConfigMap `openbao-server-ca` (`ca.crt`).
3. `helm upgrade --install openbao deploy/chart -n openbao -f deploy/chart/values-lab.yaml`
4. `python3 scripts/lab-bootstrap.py --kubeconfig KUBECONFIG --output init.json`
   (initializes 3 voters, threshold 2, and unseals them; keep `init.json` private).
5. Create a confidential Keycloak client for OpenBao, then pipe the JSON config
   (including `admin_token` and, for a private CA, `oidc_discovery_ca_pem`) to
   `scripts/configure-openbao.py --kubeconfig KUBECONFIG --public-origin https://HOST`.
6. Apply `deploy/lab/host-proxy.yaml` (replace `BIND_ADDRESS` with the node IP) and
   point DNS for the Secret Manager hostname at that address. Flash workloads
   and the HeteroCloud API reach OpenBao there with TLS passthrough:
   NetworkPolicy `ipBlock` rules are evaluated after DNAT, so a LoadBalancer VIP
   cannot be allowed through `networkPolicy.secretManagerCidrs`. The OpenBao
   server certificate must include the Secret Manager hostname as a SAN.
7. Give the HeteroCloud API the CA through `extraEnv`/`extraVolumes`
   (`SSL_CERT_FILE`) because its Secret Manager client uses the process trust store.
