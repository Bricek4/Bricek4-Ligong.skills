# 力工（Ligong）

面向 Codex 的风险自适应软件工程执行 Skill：把口语化需求收敛为明确的目标、边界和验收证据，再根据实际影响选择轻量执行或 TaskGuard 合同闭环。

力工适合修复 Bug、开发功能、安全删除、代码审查和复杂跨层修改。它重点处理开发任务中最容易被忽略的部分：保护已有改动、保持接口兼容、识别规则陷阱、隔离工作区，以及确认测试证据确实属于当前代码和当前任务。

> 力工不是新的模型，也不会扩大 Codex 的权限。它是一套执行、风险控制和验证协议。

[快速开始](#快速开始) · [使用示例](#使用示例) · [风险等级](#风险等级) · [TaskGuard](#taskguard) · [安全边界](#安全边界) · [参与开发](#参与开发)

## 为什么使用力工

普通开发请求往往只有一句“改一下”“删掉旧逻辑”或“修复这个 Bug”，但真正交付还涉及隐含问题：允许改哪些文件、旧接口是否必须兼容、删除是否覆盖残留入口、测试是否被错误修改，以及验证结果是否已经过期。

力工会根据仓库事实和最终影响处理这些问题：

- **先检查坑，再动手**：核对需求、路径、接口两端、规则冲突和潜在副作用。
- **按风险分配成本**：机械修改保持轻量；接口、权限、迁移和删除等高风险任务增加守卫。
- **保护现有工作**：识别 dirty 文件、克隆、worktree 和同名仓库，避免覆盖用户改动或写错目录。
- **把验证绑定到改动**：区分 RED、GREEN、禁止项、兼容面和工作区归属，拒绝陈旧或不匹配的证据。
- **主 Agent 最终验收**：worker 的完成声明不能代替最终 diff 检查和独立复验。

力工不承诺消除所有 Bug，也不以固定的冗长流程处理每个任务。它的目标是让执行强度与真实风险相称，并让完成结论有证据可追溯。

## 快速开始

### 环境要求

- Git
- Python 3.11 或更高版本
- 支持本地 Skill 目录的 Codex 环境

### 安装

将仓库克隆到 Codex 的个人 Skill 目录：

```bash
git clone https://github.com/Bricek4/Bricek4-Ligong.skills.git ~/.codex/skills/ligong
```

如果 `~/.codex/skills/ligong` 已经存在，请先检查并备份其中的个人修改。不要通过递归删除覆盖未知内容。

安装完成后，重新启动 Codex 或开启一个新任务，让 Skill 目录被重新发现。

### 第一次调用

在请求中直接使用 `$ligong`：

```text
$ligong 检查这个登录接口的租户越权问题，修复后保留现有兼容行为并运行相称验证。
```

也可以使用自然语言触发：

```text
让力工先检查需求和规则有没有坑，再完成修改并给出验证证据。
```

## 使用示例

### 修复 Bug

```text
$ligong 修复批量更新时数组顺序被打乱的问题，不改变接口响应结构，补充回归验证。
```

### 开发功能

```text
$ligong 为订单查询增加可选的时间范围过滤，先检查接口两端和现有测试，再实现并验证。
```

### 安全删除

```text
$ligong 删除废弃的 legacy_mode，包括入口、配置、引用和测试残留；不要修改无关代码。
```

### 复杂高风险修改

```text
$ligong 修改租户权限规则和持久化语义，检查兼容边界，启用 TaskGuard，并保留可审计证据。
```

### 只读审查

```text
$ligong 只审查当前改动，找出逻辑 Bug、规则冲突和缺失的边界，不要修改文件。
```

是否编辑文件取决于用户请求：调查、诊断和评审默认只读；修复或开发请求才授权本地编辑。发布、部署、删除外部资源或其他第三方写入仍需单独核验授权。

## 风险等级

力工根据最终影响而不是任务篇幅选择执行强度。风险在执行过程中可以升级，不能用低等级标签掩盖已经发现的高风险影响。

| 等级 | 典型任务 | 最小处理方式 |
| --- | --- | --- |
| `L0` | 状态查询、只读调查、机械小改 | 精确检查与相称验证；通常不需要 TaskGuard |
| `L1` | 普通本地行为变化、常规 Bug 修复或功能开发 | 明确变更契约；适用时建立 RED/GREEN；运行最终验证 |
| `L2` | 公共 API、数据库 schema/持久语义、身份权限、隐私安全、数据删除、AI 输出合同或高风险跨层数据流 | 增加 preflight、TaskGuard、边界矩阵、失败路径与兼容/迁移不变量 |
| `L3` | 部署、生产写入、第三方写入或其他外部不可逆动作 | 精确绑定动作、目标、环境、范围和授权，并要求回滚与健康证据；能力不足时停止 |

只读查看 API 或数据库不会自动升级到 `L2`；判断依据是实际 diff、数据写入和可观察语义是否发生变化。完整规则以 [`SKILL.md`](SKILL.md) 为准。

## TaskGuard

TaskGuard 是力工的合同验证与证据控制组件。它用于回答“这组证据是否足以支持当前任务已经完成”，而不是替代测试框架或宿主权限系统。

它可以检查和保存：

- 合同字段和能力是否满足任务要求；
- RED、GREEN、禁止项和兼容面是否来自同一任务绑定；
- 验收命令、提交、工作区和证据时间是否一致；
- 必需证据是否失败、陈旧、未知或相互冲突；
- L3 模拟流程的计划、回执链、回滚与健康门禁。

需要明确区分：

```text
TaskGuard ≠ 安全沙箱
TaskGuard ≠ 权限授予系统
TaskGuard ≠ “绝对没有 Bug”的证明
```

TaskGuard 会把受信合同中声明的验收命令作为本机子进程执行。虽然实现使用参数数组、禁用 shell，并包含超时与进程组控制，它仍不能隔离恶意命令；只应运行来自可信来源的合同。

进一步了解：

- [`references/taskguard.md`](references/taskguard.md)：TaskGuard 验收规则
- [`references/sss-runtime.md`](references/sss-runtime.md)：风险路由、证据链和完成熔断
- [`references/change-contract.md`](references/change-contract.md)：变更契约
- [`references/delegation.md`](references/delegation.md)：委派与主 Agent 复验

## 核心工程不变量

- 校验发生在副作用之前；成功状态只能在真实成功之后写入。
- 判断“是否存在”不能依赖 truthiness，必须区分缺失值与合法假值。
- 接口数组默认保留顺序和重复项，除非合同明确允许改变。
- 既有非废弃测试默认属于兼容边界；没有授权或证据时，不改名、不迁移、不弱化原断言。
- 删除任务不仅删除主实现，还要检查入口、配置、注册、导出、文档和测试残留。
- worker 的 `done` 不是完成证据；主 Agent 必须检查最终 diff，并从当前工作区重新验证。
- TaskGuard 只接受新鲜、同绑定、可复现的证据；必需项为 `FAILED`、`STALE` 或 `UNKNOWN` 时不能声明支持完成。

## 项目结构

```text
SKILL.md                 Skill 入口、风险路由与核心不变量
agents/openai.yaml       Codex 展示与调用元数据
references/              按需加载的工程、合同和交付说明
scripts/                 TaskGuard、评测与验证入口
taskguard/               TaskGuard 实现
tests/                   回归与安全测试
evals/                   风险和开发行为评测用例
```

主要入口：

- [`SKILL.md`](SKILL.md)：完整使用规则
- [`references/model-routing.md`](references/model-routing.md)：模型与推理强度路由
- [`references/forge-loop.md`](references/forge-loop.md)：复杂开发任务的 ForgeLoop 协议
- [`references/boundary-convergence.md`](references/boundary-convergence.md)：工程边界收敛
- [`references/workspace-isolation.md`](references/workspace-isolation.md)：工作区隔离守卫
- [`references/delivery.md`](references/delivery.md)：恢复、交接与交付

## 参与开发

在仓库根目录运行完整测试：

```bash
python3 scripts/run_tests.py
```

如果本机安装了 Codex 自带的 `skill-creator`，再验证 Skill 结构：

```bash
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
```

第二条命令依赖本机 Codex 安装路径；路径不存在不代表力工测试失败。提交前还应检查 Markdown 链接、未跟踪生成物和敏感信息。

## 更新

```bash
cd ~/.codex/skills/ligong
git status --short
git pull --ff-only
```

如果 `git status` 显示本地改动，请先提交、备份或明确处理冲突，不要直接覆盖个人定制。

## 安全边界

- 力工不会扩大用户授权，也不能替代 Codex、操作系统或外部服务的审批机制。
- TaskGuard v3 的 shadow、假服务 saga、conformance 和发布门禁不代表真实外部 provider 已获授权或可用。
- 缺少 provider 专属适配器、可信宿主授权、精确白名单、开放熔断和新鲜回滚/健康证据时，真实 `L3` 动作必须停止。
- 模型强度、worker 数量和测试数量都不能单独证明任务完成。
- 本项目不能保证适用于所有仓库、运行环境或生产流程；采用前应根据自身风险进行审查。

## 许可证与项目归属

当前仓库没有附带开源许可证。除非仓库所有者后续明确添加许可证，否则默认保留全部权利。

这是由社区维护的个人项目，不是 OpenAI 官方产品，也不代表 OpenAI 的认可或支持。Codex 和 OpenAI 是其各自权利人的名称或商标。
