# Agent Host Isolation

AIエージェントを、能力ベースの実行境界に置くための Agent Skill です。

**言語:** [English](../../README.md) | 日本語

## このスキルが必要な理由

プロンプトや承認ダイアログは、エージェントの判断を補助できます。しかし、hostを守る境界にはなりません。エージェントに無制限のshell、書込み可能なhost mount、認証情報、control socket、networkを渡した後で、慎重な指示によって能力を取り消すことはできないためです。

このスキルは、安全性の判断を実行環境へ移します。

```text
非信頼入力
  → 必要な能力を定義する
  → inspect または guest-build を選ぶ
  → default deny の task manifest を検査する
  → 制限済み環境で実行する
  → host-side result gate で成果物を検査する
  → 拒否を確認する adversarial test を行う
```

目標は「絶対安全」ではありません。定義した保護対象への未承認アクセスを、モデルの判断に頼らず拒否・検証できる状態にすることです。

## 隔離の仕組み

仕組みを七つの境界に分けました。各ドキュメントでは、制御対象、選択規則、失敗時の動作を説明します。

1. [capability分類とexecution profile](mechanisms/01-capability-profiles.md)
2. [read-only inputとguest-local scratch](mechanisms/02-input-and-scratch.md)
3. [networkとcredentialのdefault deny](mechanisms/03-network-and-credentials.md)
4. [result gateとhost-side broker](mechanisms/04-result-gate-and-broker.md)
5. [resource limit、watchdog、cleanup](mechanisms/05-resource-governance.md)
6. [adversarial testと検証状態](mechanisms/06-adversarial-verification.md)
7. [JustBash inspect runtime contract](mechanisms/07-just-bash-inspect-runtime.md)

## インストール

Vercel Skills CLIを使います。

```bash
npx skills add 53able/agent-host-isolation
```

## バージョン

releaseはGit tagで管理します。versionを固定してinstallする場合:

```bash
npx skills add '53able/agent-host-isolation#v0.1.0'
```

projectへのinstallでは、sourceと選択したGit refが`skills-lock.json`へ記録されます。同じskill versionを再現する必要があるprojectでは、このfileをcommitします。

projectへinstallしたskillを明示的に更新する場合:

```bash
npx skills update agent-host-isolation -p
```

releaseごとの変更は[CHANGELOG.md](../../CHANGELOG.md)で確認できます。

## 最短の使い方

### 1. タスクを分類する

必要十分なprofileを選びます。

| Profile | 用途 | 標準の境界 |
|---|---|---|
| `inspect` | 検索、parse、format、決定的な変換 | restricted/in-memory filesystem。network、認証情報、副作用なし |
| `guest-build` | install、build、test、コード生成、任意binary | 短命guest VM、read-only input、guest-local scratch、network default deny |
| `elevated-release` | 検証済み成果物に対する一件のrelease操作 | `guest-build`の制限とtask-scopedなhost-side broker |

JustBashのようなrestricted interpreterは、調査・整形タスクの能力を小さくする用途に使えます。ただしVM境界ではないため、任意のnative binaryを実行するtaskでguest VMの代わりにはなりません。

### 2. Task manifestを作る

同梱templateを複製します。

```bash
cp assets/isolation-manifest.template.json isolation-manifest.json
```

Manifest v2は`task`、`workspace`、`gateway`、`model`、`runtime`、`resources`、`resultGate`を分離します。入力snapshot、network policy、credential参照、resource enforcement担当、immutableなimage identity、result gate、audit recordを具体化します。旧v1 manifestは暗黙変換せず拒否します。

JustBashのinspect taskではManifest v2 templateを使います。

```bash
cp assets/just-bash-inspect-manifest.template.json isolation-manifest.json
```

JustBash templateも同じtop-level Manifest v2 resourceを使い、`runtime.kind`、最小snapshot、interpreter limit、`InspectBlocked`昇格policyだけを特化します。

### 3. 実行前に検査する

```bash
python3 scripts/validate-manifest.py isolation-manifest.json
```

Validatorは旧v1 manifestを拒否し、Apple ContainerとJustBashを共通Manifest v2 contractで検査します。標準JustBashでは不整合なprofile、未固定version、安全でないsnapshot、追加capability、network grant、未知のruntime field、無制限resource、host-shell fallback、不完全な昇格identityを拒否します。明示的な`network-derived` variantでは、taskに束縛したexact origin、path、method、転送量、expiry、redirect再評価、purpose、auditの制約を満たすgrantだけを許可します。

### 4. Apple Container argvを生成する

```bash
python3 scripts/apple_container_compiler.py isolation-manifest.json create
python3 scripts/apple_container_compiler.py isolation-manifest.json start
python3 scripts/apple_container_compiler.py isolation-manifest.json stats
python3 scripts/apple_container_compiler.py isolation-manifest.json stop
python3 scripts/apple_container_compiler.py isolation-manifest.json delete
```

compilerはshell文字列ではなくJSONのargv配列を返します。image digestとtask/manifest/workspace hashのlabelは常に生成され、任意の追加flagは受け付けません。Apple Containerの`--network`は宛先allowlistではないため、標準profileでは外部gateway/brokerが制御するtask専用networkを要求します。

### 5. Result gateを通して成果物を取り込む

任意binaryは選択したguest VM内だけで実行します。patch、log、生成物はguest outputへ出し、hostに取り込む前にpath、symlink、file type、size、hash、destination repositoryを検査します。

Git push、deploy、publish、外部書込み、credentialを伴う操作はguestへ渡しません。昇格操作が必要な場合は、host-side brokerがtask、destination、scope、expiry、audit recordを検証してから代理実行します。

### 6. 成功だけでなく拒否を試す

`assets/isolation-verification.template.md`を複製し、次の7種類を記録します。

1. Mount
2. Credential
3. Network
4. Command path
5. Resource
6. Supply chain
7. Side effect

対象のhost、runtime version、manifestで必要なtestがすべてpassした場合だけ、`verified for tested configuration`と記録します。未実行・未対応の項目は`blocked`または`unverified`とします。

## 重要な制約

- このrepositoryが提供するのは手順とmanifest検査です。VMやhost firewallを自動構築するものではありません。
- VMを使っても、mount、socket、credential、network、host integrationで明示的に渡した能力は利用できます。
- Restricted interpreterは能力を減らしますが、guest VMと同じ隔離境界ではありません。
- Runtime固有のflagとhostへの到達性は、対象OS・runtime versionで実測する必要があります。
- Build成功だけでは、保護対象へのアクセスが拒否された証拠になりません。

## ライセンス

[MIT](../../LICENSE) © 2026 53able
