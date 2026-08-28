# TaskGuard 验收

TaskGuard 是风险触发的确定性验收后端，不是开发引擎，也不授予权限。

## 何时启用

| 情况 | 决策 |
|---|---|
| 只读、解释、微小单文件编辑 | 不启用 |
| 普通行为变化且测试/范围清晰 | SSS 判定 L1 时不强制启用；软信号可能升级 |
| 跨层、公共合同、迁移、权限、安全 | SSS 判定 L2，必须启用 |
| 发布、外部写入、不可逆动作 | 判定 L3；使用 v3 解释能力缺口，真实动作在 provider/authority/release gate 完整前 fail closed |

从技能 catalog 的 `SKILL.md` 绝对路径解析 `ligong_skill_root`，shell 保持在目标 repo 根，只调用公开入口 `scripts/task_guard.py`。L2/L3 先按 [SSS 路由与熔断](sss-runtime.md) 运行能力探测与 preflight；契约见 [变更契约](change-contract.md)。

```bash
python3 "$ligong_skill_root/scripts/task_guard.py" doctor
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage initial --chain-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" init --state-dir "$taskguard_state_dir" --contract "$taskguard_contract"
python3 "$ligong_skill_root/scripts/task_guard.py" run --state-dir "$taskguard_state_dir" --acceptance unit --phase baseline
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage diff --chain-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" run --state-dir "$taskguard_state_dir" --acceptance unit --phase candidate
python3 "$ligong_skill_root/scripts/task_guard.py" preflight --capsule "$task_capsule" --stage final --chain-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" verify --state-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" status --state-dir "$taskguard_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" export --state-dir "$taskguard_state_dir"
```

L2 的 preflight 链与 TaskGuard 必须使用同一个 state 目录。`init` 只接受已到 initial 的 L2 链；实现和验证期间依次推进 diff/final；`verify` 只接受已到 final 的同 task 链。已有 v2 L3 state 可 `status/export/dispose`，但新版 `run/verify` 会拒绝，`status` 只能为 `UNKNOWN/L3_UNSUPPORTED`。

TaskGuard 的成功终态是 lifecycle `TERMINAL` 且 verdict `SUPPORTED`。TaskGuard v2 拒绝初始化 L3 合同；这不是 L3 被降为 L2，而是完整 authority/dry-run/rollback/health 义务尚未结构绑定。失败终态使用 `TERMINAL_ERROR`，verdict 为 `FAILED`、`STALE` 或 `UNKNOWN`；`NOT_REQUIRED` 只表示某项义务不适用。中断后先 `status`，再按事实 `dispose --verdict FAILED|UNKNOWN`，不能隐式重放。

## v3 外部动作控制面

v3 是新增协议，不原地升级 v2 state。合同必须精确声明一个 action 的 kind、adapter、canonical target、environment、desired state、preconditions、authority、plan、rollback 和 health policy；未知字段、重复 JSON key、NaN/Infinity、bool-as-int、多个 action 或无回滚的写动作都会拒绝。

```bash
python3 "$ligong_skill_root/scripts/task_guard.py" validate --contract "$taskguard_v3_contract"
python3 "$ligong_skill_root/scripts/task_guard.py" explain --contract "$taskguard_v3_contract"
python3 "$ligong_skill_root/scripts/task_guard.py" init --state-dir "$taskguard_v3_state_dir" --contract "$taskguard_v3_contract"
python3 "$ligong_skill_root/scripts/task_guard.py" status --state-dir "$taskguard_v3_state_dir"
python3 "$ligong_skill_root/scripts/task_guard.py" shadow --contract "$taskguard_v3_contract" --action "$action_id"
python3 "$ligong_skill_root/scripts/task_guard.py" provider-readiness
```

v3 每个 plan、authority、rollback readiness、apply intent、effect、reconcile、health 和 rollback 证据使用内容寻址回执；父回执缺失、内容篡改、绑定漂移或证据过期都 fail closed。apply intent 必须先持久化再调用 provider；断线不能推断未执行，只能用同一幂等键 reconcile。健康证据必须绑定准确 effect revision 并覆盖完整窗口。回滚只能把动作变成 recovered/failed，不能把原任务改成成功。

支持矩阵：

| 能力 | 状态 |
|---|---|
| v2 L2 本地验收 | 在现有平台能力检查通过时支持 |
| legacy v2 L3 | 永久不原地升级；仅 status/export/dispose |
| v3 严格合同、回执、路由、只读计划 | 已实现；默认无 adapter 时精确 `UNSUPPORTED` |
| v3 确定性 saga、reconcile、rollback、windowed health | 已实现为依赖注入内核并由假服务测试；不自动注册到生产 |
| provider conformance、沙箱隔离、shadow、白名单、熔断、生产交集门 | 已实现通用门禁 |
| 真实沙箱动作 | 未支持；需要单独批准并实现 provider 专属适配器计划 |
| 真实生产动作 | 未支持；还需要可信宿主 AuthorityProvider 和完整发布证据 |
| delete/外部不可逆动作 | 未支持，除非另行证明可恢复义务 |

默认注册表始终为空，也没有自动模块发现、通用 shell adapter、通配目标、`--force` 或调用者自写“已批准”文本的后门。`shadow` 即使为 `READY`，action verdict 仍不是 `SUPPORTED`；熔断关闭时禁止新 apply，但保留 status/export/reconcile 和已经需要的 rollback。

源码、测试、配置、锁文件、scope、argv、cwd、selector 或关键输入在通过后变化会使证据陈旧，必须对最终状态重新验证。

## 结构化降级

TaskGuard 不可用但授权允许继续可撤销的本地实现时，主 Agent 提供：完整 preflight 链、目标与允许范围、受保护改动、禁止副作用、初始状态、最终文件清单/diff、实际验证命令与退出状态、证据时间/哈希、未决风险，以及 `FAILED|UNKNOWN` 的人工结论。明确说明 TaskGuard 未运行及原因，不能把人工核验描述成 TaskGuard 通过或 `SUPPORTED`。L3 不得把这种降级用作执行外部动作的完成门。

缺少关键证据只能为 `UNKNOWN`。L3 不得因工具不可用绕过授权或回滚；不能建立等价证据时停止为未验证/阻塞。
