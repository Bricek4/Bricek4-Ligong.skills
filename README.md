# Bricek4 Ligong Skill

力工（Ligong）是面向 Codex 的软件工程执行技能。它把自然语言开发请求收敛为可观察结果，并根据风险选择轻量验证或 TaskGuard 合同闭环，重点保护既有改动、接口兼容、删除完整性、工作区隔离和证据新鲜度。

## 主要能力

- 将口语化开发请求整理为目标、范围、验收、风险和禁止副作用。
- 按 L0–L3 风险等级选择相称的执行与验证强度。
- 修复 Bug、实现功能、删除旧语义并保护非废弃测试。
- 检查接口字段、数组顺序、状态码、错误体和兼容 surface。
- 使用 TaskGuard 保存 RED/GREEN、forbidden、surface、工作区归属和新鲜度证据。
- 对克隆、worktree、同名仓库和用户既有脏文件进行隔离保护。
- 为复杂任务提供恢复、交接、发布门禁和结构化证据。

## 安装

需要 Git、Python 3.11 或更高版本，以及支持技能目录的 Codex 环境。

```bash
git clone https://github.com/Bricek4/Bricek4-Ligong.skills.git ~/.codex/skills/ligong
```

如果目标目录已经存在，请先自行备份或选择其他目录；不要用递归删除命令覆盖已有技能。

安装后重新启动 Codex，或开启一个新任务，让技能目录重新被发现。

## 使用

在请求中明确调用：

```text
$ligong 修复这个接口的租户越权问题，并保留现有兼容行为。
```

也可以使用自然语言：

```text
让力工检查需求有没有坑，完成修改并运行相称验证。
```

任务较小时，力工会保持轻量；公共接口、迁移、权限、持久化或跨层修改会升级风险闭环。TaskGuard 不授予额外权限，也不能证明合同之外绝对没有 Bug。

## 目录

```text
SKILL.md                 技能入口和风险路由
agents/openai.yaml       Codex 展示与调用元数据
references/              按需读取的工程、合同和交付说明
scripts/                 TaskGuard、评测和验证入口
taskguard/               TaskGuard 实现
tests/                   回归与安全测试
evals/                   风险和开发行为评测用例
```

## 验证

在仓库根目录运行：

```bash
python3 scripts/run_tests.py
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
```

第二条命令依赖 Codex 自带的 `skill-creator`。如果该路径不存在，至少运行完整测试，并检查 `SKILL.md` 的 YAML frontmatter。

## 安全边界

- TaskGuard 会以本机子进程执行合同中声明的验收命令；虽然使用参数数组、禁用 shell 并设置超时与进程组控制，它仍不是安全沙箱。只运行可信来源的合同和命令。
- 力工不会扩大用户授权，也不能替代宿主审批。
- L2/L3 的完成声明依赖新鲜、同绑定、可复现证据。
- TaskGuard v3 的 shadow、假服务 saga、conformance 和发布门禁不代表真实外部 provider 已获授权或可用。
- 真实不可逆外部动作仍需要精确目标、环境、范围、回滚和健康证据。
- 既有非废弃测试默认是兼容边界；没有授权或证据时，不改名、不迁移、不弱化原断言。

## 更新

```bash
cd ~/.codex/skills/ligong
git pull --ff-only
```

更新前先检查本地是否有未提交改动，避免覆盖个人定制。

## 许可证

当前仓库未附带开源许可证。除非仓库所有者后续明确添加许可证，否则默认保留全部权利。

## 项目归属

这是社区维护的个人项目，不是 OpenAI 官方产品，也不代表 OpenAI 的认可或支持。
