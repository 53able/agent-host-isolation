# strict-memory 自動振り分けゲート

自動経路は限定します。信頼できるhost controllerが`strict-memory`の`InspectBlocked`を受け取り、新しいApple Container `guest-build` manifestとattemptを検査し、source snapshotの内容を照合し、実機resource probeを通した後にだけtargetの`task.command`を実行します。guestにはnetworkとcredential brokerを渡しません。成果物はguestとresourceの停止・削除後、privateなstagingとresult gateを経由します。

`scripts/guest_build_runner.py`はcommandの実行、host wall-time・output watchdog、所有ラベルを確認したcleanup、read-only output volumeからの取出しを担当します。現在の対象profileではwall timeを30秒、logを1 MiB、importするartifactを32 MiBまでに制限します。command、取出し、cleanup、artifact検査のいずれかが失敗した場合は成功としてimportしません。

`scripts/verify_strict_memory_dispatch.py`は対象Apple Container hostで通常の`task.command`からresult gateまでの経路、wall/log watchdog、宣言されたdisk/process上限、symlink artifact拒否、cleanupを検査し、memory OOM probeと合わせます。`scripts/strict_memory_dispatch.py`は自動実行を試みるたびに実機検査をやり直し、targetのimageとresource profileが検証済み構成と一致しない場合や、checkが欠ける・失敗する場合は拒否します。attemptを永続的にclaimし、VM slotは一つに直列化します。受け入れた成果物の保存先は`/var/tmp/agent-host-isolation/imports/<task-id>/<attempt-id>`です。

記録したApple Container 1.2.2 hostでは、自動振り分けは**blocked**です。root guestは`nproc=32`でも40個のprocessを起動でき、16 MiBを指定したvolumeには40 MiBを書き込めました。volume設定は16 MiBと表示されますが、guestには約132 MiBとして見えます。宣言したprocess/disk強制契約を満たさないため、両方を解決して実機probeを再実行するまで自動実行しません。手動の昇格requestは利用できます。

このprofileのfull pathは選択された`task.command`です。一般的なagent orchestrator、network gateway、credential brokerではなく、別のimage、host、runtime version、resource profileの隔離検証にもなりません。
