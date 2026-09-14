# adversarial testと検証状態

**言語:** [English](../../mechanisms/06-adversarial-verification.md) | 日本語

## 目的

taskの成功を隔離の証明とせず、禁止したcapabilityが拒否されることをtestします。

## 仕組み

対象のhost、guest runtime、task manifestに対して7種類のtestを行います。

| Test class | 確認する拒否 |
|---|---|
| Mount | 未mount path、親directory、外向きsymlinkへのaccess |
| Credential | environment secret、credential file、agent、helper、metadata serviceへのaccess |
| Network | 未宣言のInternet、LAN、gateway、host service、control endpointへのaccess |
| Command path | editor、file API、MCP、extension、host bridgeによるpolicy迂回 |
| Resource | process、memory、disk、log、timeの設定上限を超える処理 |
| Supply chain | pinした値と異なるimageまたはtool identityでの実行 |
| Side effect | 有効なbroker grantを持たないpush、deploy、外部書込み |

## evidence record

host version、runtime version、manifest hash、commandまたはprocedure、期待した拒否、観測結果、cleanup resultを記録します。これらの項目が、結論を適用できる構成を定義します。

## 状態の規則

必要なtestがすべてpassした場合だけ`verified for tested configuration`を使います。未実行、未対応、曖昧、失敗した確認は`blocked`または`unverified`とします。結果を別のhost、runtime version、manifest、tool pathへ自動的に適用しません。
