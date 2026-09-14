# 成果物の生成とhostへの永続化を分ける

**言語:** [English](../../benefits/04-artifact-import.md) | 日本語

## 状況

AIエージェントが作ったpatch、archive、log、生成ファイルをhost repositoryへ戻します。

## 実行境界がない場合のリスク

writable repository mountは、生成と永続化を同じ操作にします。path traversal、symlink処理、destinationの誤りがあっても、検査前にhost fileが変更されます。

## このスキルによる変更

成果物をguest output storageへexportし、非信頼入力として扱います。host-side result gateがpath、symlink、file type、size、hash、destinationを検査し、意図した結果だけを取り込みます。

## 導入メリット

host変更が独立した観測可能な操作になります。guestへrepositoryの直接書込み権限を渡さず、生成内容をreviewまたはrejectできます。

## この構成だけでは証明できないこと

成果物の検査は、実際のimport経路すべてに適用する必要があります。表示されたdiffだけを確認しても、別のarchive extractorやfile bridgeがpolicyを迂回できるなら不十分です。
