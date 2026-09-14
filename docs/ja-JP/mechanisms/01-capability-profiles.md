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

## 失敗時の動作

選択したprofileでtaskを実行できなくても、より広いhost shellへ置き換えません。不足したcapabilityを記録し、強制可能な最小範囲だけを追加してmanifestを再検査します。
