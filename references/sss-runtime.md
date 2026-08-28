# SSS 路由与熔断

SSS 由任务胶囊、单向风险熔断、能力 preflight 与确定性证据后端组成。它只增加与风险相称的控制，不扩大用户授权。

## 任务胶囊

编辑前形成 `task-capsule-v1`：`outcome` 是可观察终态，`scope` 是仓库相对允许范围，`invariants` 是不得破坏的边界，`evidence` 是验收来源，`risk` 是声明等级，`signals` 是当前风险信号。L3 还要在 `external_actions` 登记 `action/target/environment/scope`，并在 `authority` 用相同字段加 `task_id/user_evidence` 精确绑定用户授权。严格结构见 [Schema](task-capsule.schema.json)。

胶囊是控制器输入，不替代 TaskGuard v2 合同。L2/L3 preflight 通过后，再用 [变更契约](change-contract.md) 绑定真实 Git repo、命令、dirty、forbidden 与 surface。

## 三次复判

1. `initial`：理解目标和授权后，任何写入前。
2. `diff`：确认真实调用链与实际 diff 后，扩大实现前。
3. `final`：所有验证后、完成声明前。

运行：

```bash
python3 "$ligong_skill_root/scripts/task_guard.py" doctor
python3 "$ligong_skill_root/scripts/task_guard.py" fuse --capsule "$task_capsule" --stage initial
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage initial --chain-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage diff --chain-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage final --chain-dir "$taskguard_state_dir"
```

`fuse` 只做无状态风险判定；它适合解释和测试，不能作为跨阶段信任根。公开 `preflight` 对 L2 强制使用固定 `--chain-dir`，在该目录以 checksummed、revisioned 状态保存 initial/diff/final；不能跳阶段、跨 task、替换前序或在同一目录重启 initial。链同时绑定 `task_id/outcome/scope/risk`；TaskGuard L2 的 `init` 要求合同的 task/goal/scope/risk 与同目录 initial 链一致。final 只能在所有 candidate evidence 为 `SUPPORTED` 后提交，并绑定当时的 task revision/checksum 与工作区快照；`verify` 重新计算这些绑定，final 后的任务或文件变化会使其陈旧。历史有效等级与硬触发只增不减。L0/L1 返回 `NOT_REQUIRED`；L2 只有风险匹配且能力完整时返回 `READY`；当前 L3 返回 `UNSUPPORTED`。输出均为稳定的 canonical JSON。

链状态与 TaskGuard 共享 `$taskguard_state_dir`。它防止正常控制流中的重启、错链和竞争更新，但不声称抵抗拥有同一操作系统账号、能任意改写代码和状态的恶意主体；该主体本就在本地工具信任边界之外。

## 硬触发、软升级与阻断

- L2 硬触发：`public_api`、`persistence`、`migration`、`identity`、`authorization`、`tenant`、`privacy`、`security`、`data_loss`、`false_supported`、`ai_output`。
- L3 硬触发：`deploy`、`delete`、`production_write`、`third_party_write`、`external_irreversible`。
- 两个软信号使 L0→L1 或 L1→L2；已经声明 L2/L3 且有两个软信号时增加独立复核。
- `scope_expansion` 始终阻断并要求重新确认；`final` 阶段的 `evidence_conflict` 始终阻断；L3 动作缺少同名 `authority` 始终阻断。

风险熔断是单向的：后续看到的信息可以升级，不能用“改动很少”“赶时间”或“没有进程”降级。要降低等级，必须新建任务胶囊并证明原硬触发不成立。

## 能力与状态语义

`doctor` 是只读探测，不加载 POSIX TaskGuard 核心。TaskGuard 当前要求 POSIX、`fcntl`、`O_NOFOLLOW`、`O_DIRECTORY`、目录 fsync、进程组、SIGTERM/SIGKILL 和 Git。任何项缺失都返回 `taskguard_supported:false`，不得输出 `SUPPORTED`。

状态词不可互换：

- `NOT_REQUIRED`：当前等级不要求 TaskGuard。
- `READY`：风险与能力允许初始化 TaskGuard，尚未验证任务。
- `RECLASSIFY`：声明风险过低，必须更新胶囊。
- `BLOCKED`：范围、证据或授权熔断。
- `UNSUPPORTED`：运行时缺少安全能力，或当前后端尚不能绑定该等级的全部义务。TaskGuard v2 当前不支持 L3 完成证明。
- `SUPPORTED`：仅由 TaskGuard 对全部必需义务的新鲜证据聚合得出。

`export --state-dir ...` 输出自带摘要的只读状态快照 `taskguard-evidence-v1`；它不创建锁、不重跑命令，也不重新证明新鲜度。快照中的持久化 `SUPPORTED` 会保守标为 `UNKNOWN/SNAPSHOT_ONLY`，不能作为独立完成证明。确定性规则覆盖见 [SSS 评测](evaluation.md)。
