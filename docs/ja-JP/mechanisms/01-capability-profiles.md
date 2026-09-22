# capability分類とexecution profile

**言語:** [English](../../mechanisms/01-capability-profiles.md) | 日本語

## 目的

すべてのtaskを同じ汎用shellで動かさず、taskが実際に必要とするcapabilityからexecution environmentを選びます。

## 仕組み

最初にtaskの要件を、入力、command、出力、network、credential、副作用、resource limitへ分けます。その結果から三つのprofileのいずれかを選びます。

| Profile | 実行要件 | 境界 |
|---|---|---|
| `inspect` | 検索、parse、format、決定的な変換 | restricted/in-memory filesystem。network、credential、副作用なし |
| `guest-build` | dependency install、build、test、コード生成、任意binary | read-only inputとguest-local scratchを持つ短命guest VM |
| `elevated-release` | build evidence取得後の明示的な外部書込み | `guest-build`の制限とtask-scopedなhost-side broker |

## 選択規則

任意のnative binaryが不要な場合だけ`inspect`を使います。package manager、compiler、test runner、生成プログラム、未知のbinaryを動かす時点で`guest-build`を選びます。`elevated-release`は指定されたrelease操作だけに使い、探索には使いません。

JustBashはManifest v2で定義する`inspect` runtimeです。HostのNode.js process内で動作し、VM境界ではありません。[JustBash runtime contract](07-just-bash-inspect-runtime.md)に従い、`guest-build`や`elevated-release`とは組み合わせません。

## 失敗時の動作

JustBashでtaskを実行できない場合は`InspectBlocked`を記録します。Native executionが必要なら、新しい`guest-build` manifestとTask attemptを作ります。Host shellへ置き換えたり、実行中attemptの権限を広げたりしません。Nativeでない追加capabilityも、別途reviewする派生profileで扱います。
