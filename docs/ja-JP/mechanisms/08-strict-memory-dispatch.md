# strict-memory 自動振り分けゲート

自動経路は限定します。信頼できるhost controllerが`strict-memory`の`InspectBlocked`を受け取り、新しいApple Container `guest-build` manifestとattemptを検査し、source snapshotの内容を照合し、実機resource probeを通した後にだけtargetの`task.command`を実行します。guestにはnetworkとcredential brokerを渡しません。成果物はguestとresourceの停止・削除後、privateなstagingとresult gateを経由します。

`scripts/guest_build_runner.py`はread-only containerに容量固定のscratch/output tmpfsと1 MiBの`/dev/shm`を設定し、固定のroot idle processを起動します。`task.command`はUID 1000で実行し、process数とopen-file数のhard limitを設定します。taskの子processが残っていないことを確認し、containerの稼働中にoutputを取り出します。hostのwall-time・output watchdogと所有ラベルを確認したcleanupを経て、result gateでimportします。現在の対象profileではwall timeを30秒、logを1 MiB、importするartifactを32 MiBまでに制限します。command、取出し、cleanup、artifact検査のいずれかが失敗した場合は成功としてimportしません。

`scripts/verify_strict_memory_dispatch.py`は対象Apple Container hostで`task.command`からresult gateまで、wall/log watchdog、process/open-file/CPU/VM数の上限、scratch/output/共有メモリのdisk上限、7種類の敵対的検証、artifact拒否、子processの終了確認、cleanupを検査し、memory OOM probeと併せて確認します。`scripts/strict_memory_dispatch.py`は自動実行を試みるたびに実機検査をやり直し、JustBash host controllerが発行したprivateなevent recordを要求します。targetのimageとresource profileが検証済み構成と一致しない場合や、checkが一つでも欠けるか失敗した場合は拒否します。attemptを永続的にclaimし、VM slotの使用を一つに直列化して、privateな監査記録を書きます。受け入れた成果物の保存先は`/var/tmp/agent-host-isolation/imports/<task-id>/<attempt-id>`です。

以前のnamed volume/root経路はApple Container 1.2.2で制限が機能しませんでした。`nproc=32`のroot guestは40個のprocessを起動でき、16 MiB指定のvolumeには40 MiBを書き込めました。compilerは通常のstrict-memory taskでこの経路を拒否します。`create-probe`だけをmemory OOM実験用の明示的な入口として残します。新しいtmpfs/非root経路では同じhostで、拒否を確認するprobeが通過しました。JustBash inspect runtime作成時に検証済みの`strictMemoryTargetManifest`を設定すると、host controllerによる`blockInspectForStrictMemory`がゲート付きdispatchを自動起動し、`strictMemoryDispatchResult`で結果を取得できます。target未設定時は手動の昇格requestのままです。`scripts/verify_strict_memory_auto.py`でeventから成果物の取り込みまでを実機検査します。

実機でeventから成果物の取り込みまでを通した[記録](../../../evidence/strict-memory-auto-event-20260923.md)に、27項目のpass結果を保存しています。このprofileのfull pathは選択された`task.command`です。一般的なagent orchestrator、network gateway、credential brokerではなく、別のimage、host、runtime version、resource profileの隔離検証にもなりません。
