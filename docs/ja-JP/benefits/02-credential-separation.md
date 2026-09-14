# 通常の実行から認証情報を切り離す

**言語:** [English](../../benefits/02-credential-separation.md) | 日本語

## 状況

buildを行うMacには、SSH key、cloud token、Gitの認証情報、署名権限も保存されています。

## 実行境界がない場合のリスク

environment variableの継承やsocket forwardingによって、taskへ作業者の長期的な権限まで渡ることがあります。依存パッケージや注入されたコマンドが侵害された場合、buildと無関係なsystemにも認証できてしまいます。

## このスキルによる変更

通常のguest実行ではcredentialをdenyします。認証が本当に必要な操作は、host-side brokerへ限定されたrequestとして渡します。requestをtask、destination、scope、expiry、audit recordに結び付けます。

## 導入メリット

通常のbuildとtestが長期credentialを継承しなくなります。昇格権限を探索的な実行から切り離し、指定した一件の操作に限定できます。

## この構成だけでは証明できないこと

broker自身がrequest schemaとscopeを強制する必要があります。credentialをguestの外へ移しても、brokerが任意の宛先や操作を受け付ければ境界にはなりません。
