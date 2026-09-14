# 「buildが成功した」から「境界が機能した」へ進む

**言語:** [English](../../benefits/06-boundary-evidence.md) | 日本語

## 状況

選択したexecution environmentでbuildが正常に完了しました。

## adversarial verificationがない場合のリスク

成功から分かるのは、期待した経路が動いたことだけです。禁止したpath、credential、network、command bridge、副作用へ到達できないことまでは分かりません。

## このスキルによる変更

mount、credential、network、command path、resource、supply chain、side effectの7種類の拒否testを行います。host version、runtime version、manifest hash、command、観測結果、cleanup resultを記録します。

## 導入メリット

隔離の主張が、全体的な印象ではなく対象を限定したevidenceになります。どの構成をtestし、何が未確認なのかをreviewerが追跡できます。

## この構成だけでは証明できないこと

evidenceは、別のOS、runtime version、manifest、tool pathへ自動的に引き継げません。未実施・未対応の確認は`blocked`または`unverified`と記録します。
