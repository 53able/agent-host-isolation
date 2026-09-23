# resource limit、watchdog、cleanup

**言語:** [English](../../mechanisms/05-resource-governance.md) | 日本語

## 目的

filesystem、credential、networkの境界を越えなくてもhost capacityを消費するworkloadに、上限を設けます。

## 仕組み

task manifestで次の上限を定義します。

- CPU
- memory
- process count
- disk usage
- log volume
- concurrent VM count
- wall time

host-side watchdogがworkloadを観測し、停止条件を強制します。完了、失敗、timeoutの後に、guest、scratch storage、一時network grant、短期credentialをcleanupします。

## 責任分界

guest runtimeは、対応しているresource controlを強制します。host schedulerは、VM count、蓄積log、timeout処理、cleanupなどfleet全体の制御を担います。一つのruntime flagがすべてのlimitを扱うとはみなしません。

## 失敗時の動作

limitを超えたらworkloadを終了し、容量を制限した診断evidenceを保存してcleanupします。必要なlimitを対象runtimeで強制できない場合は、そのcontrolを`blocked`と記録するか、より強いexecution hostを選びます。
