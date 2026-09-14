# 資源を使い切る前に停止する

**言語:** [English](../../benefits/05-resource-limits.md) | 日本語

## 状況

build、test、生成コマンドが、process、memory、disk、log、wall timeを消費し続けます。

## 実行境界がない場合のリスク

保護対象のfileやcredentialへ触れなくても、taskはhost resourceを枯渇させられます。AI自身が暴走に気づいて停止するまで待つ方法は、確実な停止条件になりません。

## このスキルによる変更

実行前にCPU、memory、process、disk、log volume、VM count、wall timeの上限を定義します。完了、失敗、timeoutに対するhost-side watchdogとcleanup actionも決めます。

## 導入メリット

resource failureの上限と復旧経路を事前に決められます。実行前にtaskの最大footprintを確認できます。

## この構成だけでは証明できないこと

設定値が対象runtimeで本当に強制されるかを試す必要があります。未対応、未強制、cleanup対象外のlimitは`unverified`です。
