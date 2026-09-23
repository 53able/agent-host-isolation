# Inspect fetch Issue #5 adversarial evidence

Status: `verified-for-tested-configuration`

all required broker and runtime probes passed with committed execution inputs

Runtime: Node 24.13.1, JustBash 3.4.2

| Probe | Expected | Observed | Passed |
|---|---|---|---|
| `origin-deny` | `denied` | `denied` | `True` |
| `path-deny` | `denied` | `denied` | `True` |
| `method-deny` | `denied` | `denied` | `True` |
| `dns-ip-literal` | `denied` | `denied` | `True` |
| `alternate-port` | `denied` | `denied` | `True` |
| `redirect-hop-deny` | `denied` | `denied` | `True` |
| `header-credential-deny` | `denied` | `denied` | `True` |
| `expiry-deny` | `denied` | `denied` | `True` |
| `byte-budget-deny` | `denied` | `denied` | `True` |
| `dns-timeout-deny` | `denied` | `denied` | `True` |
| `cancel-deny` | `denied` | `denied` | `True` |
| `request-timeout-deny` | `denied` | `denied` | `True` |
| `gate-and-real-just-bash` | `allowed` | `allowed` | `True` |
| `live-example-com` | `allowed` | `allowed` | `True` |
| `live-redirect-hop` | `denied-after-redirect` | `denied` | `True` |
| `live-origin-deny` | `denied` | `denied` | `True` |
| `live-path-deny` | `denied` | `denied` | `True` |
| `live-method-deny` | `denied` | `denied` | `True` |
| `live-ip-literal-deny` | `denied` | `denied` | `True` |
| `live-alternate-port-deny` | `denied` | `denied` | `True` |
| `live-header-deny` | `denied` | `denied` | `True` |
| `live-expiry-deny` | `denied` | `denied` | `True` |
| `live-byte-budget` | `denied` | `denied` | `True` |
| `live-dns-timeout` | `denied` | `denied` | `True` |
| `live-request-timeout` | `denied` | `denied` | `True` |
| `live-cancel` | `denied` | `denied` | `True` |

The deterministic legacy matrix uses injected transport. The live matrix uses the real broker, resolver, and HTTPS connection where policy permits one. Pre-connect denials have zero traced resolver/socket calls; denied results have no allowed/result-gate event and a durable revocation after broker exit. The successful fetch crosses the one-shot gate into installed standard JustBash. Verification applies only to the captured runtime, host, manifests, snapshots, and committed execution inputs; a failed or incomplete rerun returns to `unverified`.
