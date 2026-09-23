# Controller-triggered strict-memory dispatch

On 2026-09-23, commit `471bcab173055adbb4e3130789bd8d8cf5cd8a1c` was clean before `python3 scripts/verify_strict_memory_auto.py --output /tmp/ahi-strict-memory-auto-event-20260923.json` ran on the recorded Apple Container host.

The JustBash host controller issued an `InspectBlocked` event with `missing_capability: strict-memory`. A target manifest was preconfigured in `createInspectRuntime`, so `blockInspectForStrictMemory` called the guarded dispatcher without a separate dispatch command. The dispatcher reran the live memory probe and all 27 required checks. Every check passed, including process, disk, CPU, open-file, VM-count, adversarial, cleanup, and `full_agent_path` checks. The target `task.command` copied the declared snapshot file into `/output/result.txt`; the result gate imported it with SHA-256 `4c848e15091f330b74497fe6ee5744839fd7d64eb00a90b54087c038538d03a8`.

The complete outcome is in [the JSON record](strict-memory-auto-event-20260923.json). This proves the configured event-to-import path on this host, runtime, image, and resource profile. Each future automatic attempt reruns the gate and blocks if the tested configuration or any required check differs or fails. No target manifest means no automatic dispatch.
