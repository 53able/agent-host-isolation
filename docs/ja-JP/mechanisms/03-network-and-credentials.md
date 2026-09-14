# networkとcredentialのdefault deny

**言語:** [English](../../mechanisms/03-network-and-credentials.md) | 日本語

## 目的

通常のagent実行が、外部service、internal network、認証済みsystemへの暗黙的なaccessを継承しないようにします。

## networkの仕組み

networkをdenyした状態から始めます。接続が必要な場合だけ、destination、protocol、port、method、purposeをmanifestへ追加します。Internet、LAN、host gateway、host service、runtime control endpointは、別々の到達経路としてtestします。

## credentialの仕組み

SSH-agent socket、cloud token、Git credential helper、signing key、secret environment variableをguestへ渡しません。認証を伴う副作用が必要な場合は、credentialを公開せず、限定されたrequestをhost-side brokerへ渡します。

## 選択規則

一般にtoolが要求するからではなく、task内の特定stepが必要とする場合だけcapabilityを追加します。そのstepがtaskからなくなったらgrantも削除します。

## 失敗時の動作

接続拒否やcredential不足は、capability要件が満たされていない証拠です。対象operationを特定し、blockedのままにするか、より狭いgrantを追加します。無制限egressや長期credential forwardingで解決しません。
