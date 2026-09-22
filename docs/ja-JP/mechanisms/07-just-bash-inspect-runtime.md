# JustBash inspect runtime

**言語:** [English](../../mechanisms/07-just-bash-inspect-runtime.md) | 日本語

## 境界

`runtime.kind: just-bash`は`inspect`専用のin-process interpreterです。上限付きの検索、text processing、structured dataのparse、hash計算、決定的変換に使います。VMやOS security boundaryではなく、package manager、compiler、test runner、native binary、生成program、VM境界を必要とするworkloadには使いません。

このruntimeでは`assets/just-bash-inspect-manifest.template.json`を使います。Manifest v2はtask identity、最小input snapshot、Gateway grant、runtime capability、result gate、audit event、verification statusを分離します。validatorは未知のv2 fieldを黙って許可せず拒否します。

## 標準capability

標準profileが公開するのは宣言済みsnapshotだけです。filesystemはin-memory、または作成済みsnapshotだけをrootとするoverlayです。書込みはtask-localなvirtual overlayに残します。repository root、親workspace、home directory、host environment、child process、native binary、control socket、credentialは公開しません。

Network、JavaScript、Python、custom command、tool invocationは無効です。標準validatorはnetwork attachmentとgrantをすべて拒否します。`network-derived`はgrant宣言が妥当でも現在は拒否します。JustBashにはexact origin、path、method、expiry、転送量、redirect各hopの再評価を実行時に強制するGateway adapterがありません。grant宣言だけでnetwork accessは有効になりません。full Internet accessは常に無効です。その他の追加capabilityも別途仕様化・reviewした派生profileで扱い、実行中の標準attemptを変更しません。

ManifestはJustBash package、Node.js、agent-host-isolation、input snapshotのidentityを固定します。`execution_limit_profile: hardened`を選び、call depth、command count、source、filesystem、output、archive、database、wall-clock、extension cleanupの上限を固定します。Templateの初期値は敵対的test harnessで使用した値（call depth 8、command 32、source/output 4 KiB、filesystem 128 KiB、archive/database 32 KiB、execution 1秒、cleanup 25 ms）です。Validatorの最大値は推奨初期値ではなく上限です。In-processの制限だけではhost全体のmemory上限にはならず、host exhaustionへの耐性を主張する前にhost watchdog/worker processが必要です。上限超過はattempt失敗であり、部分outputを成功artifactとして扱いません。

## Snapshotとresult flow

HostはJustBash起動前にsnapshotを作ります。各entryにはrelative path、regular fileまたはdirectoryのtype、size、hashを記録します。absolute path、parent traversal、home-relative path、symlink、device、socket、FIFOを拒否します。Archive展開はvirtual filesystem内と展開上限内に限定します。

Filesystem差分とexport artifactは非信頼outputです。Hostへ取り込む前にresult gateでpath、symlink、type、size、hash、destinationを検査します。Runtimeはhost repositoryへ直接書き込みません。

## 失敗と昇格

Host側の`scripts/just_bash_runtime.mjs` adapterは、単一のJustBash command-not-found（exit 127）を`InspectBlocked`に変換します。先行する副作用の後に127で終了した複合commandは昇格signalではなく失敗として扱います。AdapterはJustBash instanceだけを受け取り、host executorは受け付けません。Host shellへfallbackせず、現在のattemptの権限も広げません。Native executionが必要なら、**同じTask ID**で新しい`guest-build` manifest、manifest hash、Task attemptを作り、Apple Container runtimeとして再検査してから実行します。昇格はrequestであり、自動許可ではありません。

Target manifestの検査後、記録した`InspectBlocked` JSON eventをsource/target manifestと一緒に`scripts/just_bash_contract.py`へ渡します。Generatorはeventのsource Task/attempt/manifest hashとmissing capabilityを検証し、attempt IDの再利用や異なるTask IDを拒否します。Blocked event hashと両manifestのidentityを記録しますが、runtimeは実行しません。

1 Task sessionが1 JustBash instanceを所有します。Filesystemと明示的Task stateはexportできますが、shell environment、function、working directory、process memory、実行途中commandをcheckpointとは扱いません。Resume時はmanifest、runtime version、input snapshotのhash一致を要求します。

## 証跡

Task/attempt ID、manifest/input hash、runtime version、正規化済みcommand metadata、exit code、duration、limit violation、bounded stdout/stderr hash、filesystem diff、artifact、result-gate decision、cleanup outcomeを関連付けます。AST command collectionはaudit補助であり、security enforcementの唯一の根拠にはしません。

対象package、Node.js、host、manifest、snapshot、embedding configurationで敵対的testを実行するまで、statusは`unverified`または`blocked`です。Runnerは生成するmanifest/evidence以外の実行入力がcommit済みtreeと異なる場合、verified結果を拒否します。`verified-for-tested-configuration`には、canonical executable-manifest hash、snapshot hash、runtime version、7 test class、cleanup resultが一致する構造化recordを要求します。Validator成功はcontract整合性を示しますが、escape不能を証明しません。
