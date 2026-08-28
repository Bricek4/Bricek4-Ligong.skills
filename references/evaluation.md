# SSS 评测

## ForgeLoop 开发评测

运行 `python3 -B scripts/run_development_evals.py` 检查 C0–C3、候选竞争、需求追踪与条件验证 lanes。默认语料位于 `evals/development-cases.json`；runner 拒绝重复 JSON 键、布尔版本、空期望和畸形包含断言，避免自定义语料假绿。该结果只评价开发胶囊，不代替真实代码测试。

## 风险路由评测

`evals/risk-cases.json` 是确定性路由语料，覆盖四个等级、三次复判阶段、L2/L3 硬触发、双软信号升级、独立复核、scope 扩张、证据冲突、跨阶段链和 L3 目标授权匹配。

从任意工作目录运行：

```bash
python3 "$ligong_skill_root/scripts/run_evals.py"
```

退出码 0 表示每个 case 的期望字段都与 `evaluate_risk` 一致。该评测证明规则实现与语料一致，不证明具体软件任务已经完成；具体任务仍需相称测试与 TaskGuard 证据。
