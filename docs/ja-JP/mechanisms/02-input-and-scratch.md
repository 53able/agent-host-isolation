# read-only inputとguest-local scratch

**言語:** [English](../../mechanisms/02-input-and-scratch.md) | 日本語

## 目的

guestがtaskに必要なfileを読めるようにしながら、host repositoryや無関係なhost pathへの直接書込みを防ぎます。

## 仕組み

必要なrepository pathだけを含むtask snapshotを作り、read-onlyでmountします。hostのhome directoryと親workspaceはguestへ渡しません。dependency cache、build output、一時file、中間stateは、容量制限付きのguest-local scratchへ置きます。

```text
host repository
  → 最小のread-only snapshot
  → guest execution
  → guest-local scratchとoutput
```

input snapshotとscratchは役割が異なります。snapshotは変更しないsource materialです。scratchはguestが所有し、破棄できる作業領域です。

## 取込境界

出力を回収するためにhost repositoryをwritable mountにしません。必要なartifactをguest storageからexportし、result gateで検査します。

## 失敗時の動作

buildがread-only inputを書き換えようとした場合、必要な一時pathをguest scratchへ変更します。source変更が必要なら、hostを直接変更せず、その差分をartifactとしてexportします。
