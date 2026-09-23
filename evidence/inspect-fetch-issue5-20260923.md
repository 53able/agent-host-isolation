# Inspect fetch Issue #5 adversarial evidence

Status: `unverified`

the full denial matrix uses injected transport; live example.com HTTPS and httpbin redirect probes were attempted, but this does not establish production-equivalent coverage for every required class

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

Every denial records durable audit events and revocation. The example.com success path runs through the real broker process, result gate, and installed JustBash runtime. The live redirect probe must produce a durable redirect event followed by hop reauthorization denial; overall status remains unverified because the full required class matrix is not production-equivalent.
