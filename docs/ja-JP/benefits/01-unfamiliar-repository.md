# 未知のリポジトリを、host全体へ触れさせずに実行する

**言語:** [English](../../benefits/01-unfamiliar-repository.md) | 日本語

## 状況

まだ信頼していないリポジトリで、AIエージェントに依存パッケージの導入とtestを任せます。

## 実行境界がない場合のリスク

host上で直接実行すると、そのprocessから利用できるpathやserviceまでAIの実行範囲に入ります。リポジトリの内容や生成コマンドが想定外に動いた場合、taskが必要とする範囲を超えて影響が及びます。

## このスキルによる変更

`guest-build` profileを使います。guestには読み取り専用のtask snapshotとguest-local scratchだけを渡します。hostのhome directory、親workspace、認証情報、control socketは渡しません。

## 導入メリット

buildとtestに必要な能力だけを渡し、host全体を実行範囲から外せます。想定外の動作が起きた場合も、影響範囲が小さく明示された状態から対応できます。

## この構成だけでは証明できないこと

guest VMを使うだけでは十分ではありません。writable mount、転送socket、credential、無制限networkを追加すればguestの権限は広がるため、task manifestで制御する必要があります。
