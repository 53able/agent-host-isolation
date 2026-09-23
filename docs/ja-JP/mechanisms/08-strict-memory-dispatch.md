# strict-memory 自動振り分けゲート

自動経路は限定します。信頼できるhost controllerが`strict-memory`の`InspectBlocked`を受け取り、新しいApple Container `guest-build` manifestとattemptを検査し、source snapshotの内容を照合し、実機resource probeを通した後にだけtargetの`task.command`を実行します。guestにはnetworkとcredential brokerを渡しません。成果物はguestとresourceの停止・削除後、privateなstagingとresult gateを経由します。

`scripts/guest_build_runner.py`はread-only containerに容量固定のscratch/output tmpfsと1 MiBの`/dev/shm`を設定し、固定のroot idle processを起動します。`task.command`はUID 1000で実行し、process数とopen-file数のhard limitを設定します。taskの子processが残っていないことを確認し、containerの稼働中にoutputを取り出します。hostのwall-time・output watchdogと所有ラベルを確認したcleanupを経て、result gateでimportします。現在の対象profileではwall timeを30秒、logを1 MiB、importするartifactを32 MiBまでに制限します。command、取出し、cleanup、artifact検査のいずれかが失敗した場合は成功としてimportしません。

`scripts/verify_strict_memory_dispatch.py`は対象Apple Container hostで通常の`task.command`からresult gateまでの経路、wall/log watchdog、process上限、scratch/output/共有メモリのdisk上限、symlink・予期しない・容量超過のartifact拒否、失敗taskや子processが残ったtaskのoutput拒否、cleanupを検査し、memory OOM probeと合わせます。残る7種類の敵対的検証とresource上限は、実測するまで`unverified`です。`scripts/strict_memory_dispatch.py`は自動実行を試みるたびに実機検査をやり直し、JustBash host controllerが発行したprivateなevent recordを要求し、targetのimageとresource profileが検証済み構成と一致しない場合や、checkが欠ける・失敗する場合は拒否します。attemptを永続的にclaimし、VM slotは一つに直列化し、privateな監査記録を書きます。受け入れた成果物の保存先は`/var/tmp/agent-host-isolation/imports/<task-id>/<attempt-id>`です。

以前のnamed volume/root経路はApple Container 1.2.2で制限が効きませんでした。`nproc=32`のroot guestは40個のprocessを起動でき、16 MiB指定のvolumeには40 MiBを書き込めました。compilerは通常のstrict-memory taskでこの経路を拒否します。`create-probe`だけをmemory OOM実験用の明示的な入口として残します。新しいtmpfs/非root経路では同じhostでprocessとdiskの拒否probeが通過しました。ただし残る7種類の敵対的検証とCPU、open-file、VM数の上限を同じ経路で検証するまで、自動振り分けは**blocked**です。手動の昇格requestは利用できます。

このprofileのfull pathは選択された`task.command`です。一般的なagent orchestrator、network gateway、credential brokerではなく、別のimage、host、runtime version、resource profileの隔離検証にもなりません。
