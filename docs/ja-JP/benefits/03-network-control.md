# networkを常時開放せず、必要な宛先だけを追加する

**言語:** [English](../../benefits/03-network-control.md) | 日本語

## 状況

package installやAPIを使うtestが、registryや外部serviceへの接続を必要とします。

## 実行境界がない場合のリスク

無制限のegressは、外部service、local network、host-facing endpointへ到達する未審査の経路になります。どの依存関係やtestが通信を必要としたのかも見えにくくなります。

## このスキルによる変更

networkをdenyした状態から始めます。接続不足で実行が失敗した場合、必要なdestination、protocol、port、method、purposeをtask manifestへ追加します。不要になったgrantは削除します。

## 導入メリット

network capabilityがmachineの暗黙的な性質ではなく、確認できる設定になります。失敗結果から、taskが実際に必要とする通信を特定できます。

## この構成だけでは証明できないこと

allowlistは、redirect、DNS、host gateway、local serviceを含め、対象runtimeで実測する必要があります。設定名だけではnetwork isolationを証明できません。
