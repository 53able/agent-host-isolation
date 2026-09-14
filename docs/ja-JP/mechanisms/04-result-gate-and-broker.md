# result gateとhost-side broker

**言語:** [English](../../mechanisms/04-result-gate-and-broker.md) | 日本語

## 目的

非信頼artifactの生成を、hostへの永続的な変更と認証付きの外部副作用から分離します。

## result gateの仕組み

guestはpatch、archive、log、生成fileを指定outputへexportします。hostはすべてのartifactを非信頼入力として扱い、次を検査します。

- destination repositoryとpath
- path traversalとsymlinkの解決先
- file typeとsize
- hashとsource identity
- 要求されたdiffまたはoperation

検査を通った結果だけをhost repositoryへ取り込みます。

## brokerの仕組み

Git push、deploy、publish、POST、DELETE、signingなど、credentialを伴う操作はguestの外に残します。host-side brokerはstructured requestを受け取り、task、destination、scope、expiry、audit recordを検証してから一件の許可済み操作を実行します。

## 失敗時の動作

想定したdestinationやlimitと一致しないartifactは拒否します。期限切れ、宛先違い、過大な操作、必要なevidence不足のbroker requestも拒否します。
