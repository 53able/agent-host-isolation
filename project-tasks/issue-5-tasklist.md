# Issue #5 remaining task checklist

Issue: [network-derived inspect 用の request-time gateway を実装・検証する](https://github.com/53able/agent-host-isolation/issues/5)

## Exact issue requirements

> PR #4 の標準 JustBash `inspect` は network を拒否し、`network-derived` も grant schema の検証に留めて実行を fail-closed で拒否している。request-time enforcement がない状態で有効化しない。
>
> ### 対応範囲
> - host-side fetch broker / gateway の境界と、必要なら読み取り専用 snapshot import を設計する
> - grant を Task/attempt、purpose、audit record、expiry、exact origin（scheme/host/port）、path、HTTP method、byte budget に束縛する
> - DNS/IP literal、alternate port、redirect の各 hop、credential/header 上書きを request-time に再評価する
> - 失敗・timeout・cancel 時に grant を失効させ、結果は result gate で検証する
> - 実 runtime の敵対的テストを記録し、未実施なら `unverified` のままにする
>
> ### 受け入れ条件
> - request-time enforcement と redirect 再評価が実装・テストされるまで `network-derived` は実行不可
> - 標準 `inspect` の default-deny network は不変
> - 許可外 origin/path/method、期限切れ、redirect、byte budget 超過の拒否証跡を残す

## Baseline before remaining work at `b832257`

Completed in `7e37b33`, `fb36e09`, and `b832257`:

- [x] Grant schema binds network grants to Task/attempt, purpose, audit record, expiry, origin, port, path prefix, methods, and byte budget.
- [x] Host-only HTTPS broker exists with request-time checks for origin/path/method/attempt/purpose/expiry, public DNS resolution, IP literal denial, caller-header denial, redirect-hop re-evaluation, cumulative byte budget, timeout, cancellation, and revocation.
- [x] Broker tests cover allowed fetches and denial cases; returned records remain `result_gate: pending` and `verification: unverified`.
- [x] Standard `inspect` remains networkless/default-deny, and the documentation explicitly keeps `network-derived` unavailable.

## Completed work, in dependency order

### 1. Persist and validate broker audit evidence — PASS (78 Python tests; QA attempt 3)

- [x] Replace the broker's process-local `audit` list with an append-only, task/attempt-bound audit sink, or add a validated export path that persists every allowed, redirect, denied, timeout, cancel, byte-budget, and revoke event.
- [x] Define the audit record schema and atomicity guarantees: one unique audit record per grant, manifest hash, task/attempt IDs, normalized request/hop data, decision, reason, byte counts, and cleanup/revocation outcome.
- Validation: kill/restart the broker after a denial and verify the persisted record remains readable, is bound to the original manifest/task/attempt, and cannot be reused for another attempt; assert every issue-required denial has a durable record.

### 2. Give DNS resolution its own host deadline and cancellation path — PASS (83 Python tests; QA attempt 2)

- [x] Enforce the attempt deadline while `getaddrinfo` is running, with an independent bounded DNS timeout and cancellation behavior; prevent a resolver hang from bypassing the broker's total deadline.
- [x] Record DNS timeout/cancel/failure decisions in the audit sink and revoke the grant on each failure.
- Validation: inject a resolver that blocks longer than the DNS deadline and one that observes cancellation; assert no connection is created, the call fails closed, the grant is revoked, and the durable audit event identifies the reason.

### 3. Integrate returned bytes with snapshot import and result gate — PASS (86 Python + 16 Node tests; QA attempt 2)

- [x] Define and implement the host boundary that accepts only the broker's bytes plus identity record, validates the pending result through the result gate, and creates a new read-only, networkless standard `inspect` manifest/input snapshot.
- [x] Bind the imported snapshot to the same Task ID and a new attempt/manifest identity; reject unreviewed, tampered, replayed, or over-budget records before JustBash construction.
- [x] Keep the broker unable to pass a network handle or directly enable `network-derived` in JustBash.
- Validation: successful import produces a content/hash-checked snapshot and standard networkless manifest; result-gate rejection produces no runtime; mutate bytes, record hash, task/attempt, or manifest and assert fail-closed rejection with audit evidence.

### 4. Add real-runtime adversarial evidence — PASS (verified for the tested configuration; independent QA)

- [x] Run and record tests against the exact JustBash package, Node.js version, host, manifest, snapshot, and embedding configuration for the broker/import path: origin/path/method, DNS/IP literal, alternate port, every redirect hop, header/credential override, expiry, byte budget, timeout, cancellation, and cleanup/revocation. The real broker matrix and gate-to-standard-JustBash path passed all 26 probes; deterministic injected-transport probes remain as supplementary evidence.
- [x] Require a complete passing live matrix and committed execution inputs before setting `verified-for-tested-configuration`. An incomplete, failed, or dirty rerun returns to `unverified`.
- Validation: evidence contains package/runtime/host/manifest/snapshot hashes, all required live decisions, and cleanup results; the verifier accepts `verified-for-tested-configuration` only when every required class passes against committed execution inputs and exact identities match.

### 5. Decide and implement the explicit enablement gate — PASS (fail closed; QA verified)

- [x] Keep direct `network-derived` JustBash execution rejected; the host broker is the supported request-time gateway path.
- [x] Retain the fail-closed rejection and document the supported boundary. The broker-result bridge consumes a registered, active grant's allowed event through the one-shot result gate and constructs a new standard, networkless `inspect` attempt; replay and revoked grants are denied.
- Validation: direct `network-derived` runtime construction remains rejected before and after gate integration; standard `inspect` remains default-deny. The host broker-to-gate-to-standard-runtime path and required live denial matrix are verified for the captured configuration.

## Scope boundaries

- Included: host-side read-only fetch, grant enforcement, redirect/DNS/header controls, snapshot import, result-gate validation, auditability, revocation, and exact-runtime adversarial evidence for Issue #5.
- Excluded: enabling arbitrary Internet access, passing network handles into JustBash, POST/PUT/DELETE or credentialed requests, writable host mounts, automatic production deployment, and unrelated runtime capabilities.

## Stop condition

Issue #5 can be considered complete only when every remaining checkbox is satisfied, the required live-runtime evidence is recorded, the result gate accepts only identity-matched bytes, standard `inspect` default-deny tests still pass, and `network-derived` is either enabled solely through that validated gateway or remains explicitly fail-closed with the blocking evidence documented.
