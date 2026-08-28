# SSS / TaskGuard v2 变更契约

SSS 的任务胶囊负责风险路由，L1–L3 都应先形成简短人工变更契约。L2 preflight 为 `READY` 后再创建本 JSON 合同；它是控制器与 TaskGuard 的规范绑定，完整字段由 [JSON Schema](task-contract.schema.json) 做结构预检，再由运行时 `validate_contract` 做真实仓库、Git 与文件系统校验。当前 L3 preflight 为 `UNSUPPORTED`，TaskGuard v2 会拒绝初始化 L3 合同。

```json
{
  "version": 2,
  "task_id": "cache-expiry-v2",
  "goal": "过期缓存被重新计算且声明检查通过",
  "risk": "L1",
  "repo": "/absolute/path/to/repo",
  "scope": ["src/**", "tests/**", "config/**"],
  "acknowledge_dirty": [],
  "acceptance": [
    {
      "id": "unit",
      "argv": ["python3", "-m", "unittest", "-q", "tests.test_cache"],
      "cwd": ".",
      "selector": "tests.test_cache",
      "requires_red": true,
      "expected_red_pattern": "AssertionError: expired entry was reused",
      "idempotent": true
    }
  ],
  "forbidden": [],
  "surfaces": []
}
```

## 字段与绑定

- `version` 固定为整数 `2`；`task_id`、acceptance/forbidden/surface ID 在各自集合内唯一。
- `goal` 是可观察终态；`risk` 为 L0–L3。L0 合同可解析，但正常流程不启动 TaskGuard。
- `repo` 运行时必须解析为 Git 工作树根。scope、cwd、glob 与 allowed_writes 是规范化 POSIX 仓库相对路径；拒绝绝对路径、`..`、Git 管理路径、祖先 symlink、逃逸 symlink、nested repo 与未声明 submodule。
- `argv` 必须是非空字符串数组，执行固定 `shell=False`；不得把 shell 字符串或秘密放入 argv。`cwd` 必须是已有真实目录。
- `selector` 绑定测试选择器；`requires_red: true` 时必须给非空字面 `expected_red_pattern`。RED 与 GREEN 使用完全相同的 acceptance 绑定。
- `idempotent` 必须是真布尔值，只记录 acceptance 动作是否可重复，不授予重放权限。TaskGuard 公共技能流程不因传输字符串自动重放；运行中断先执行 `status`，再用 `dispose` 固化 FAILED/UNKNOWN，存在未知副作用时不重放。

## Dirty、scope 与归属

任务不需编辑的既有 dirty 文件必须是 protected out-of-scope：保存原始字节/哈希，不把它放进 scope 或 `acknowledge_dirty`，并在结束时逐字节复验。init 拒绝未确认的 scope 内既有 dirty 路径；只有任务确实必须重叠时才用 `acknowledge_dirty`，它仅表示控制器知道冲突，不能证明修改作者，该路径归属保持 UNKNOWN，因此完整聚合不能 SUPPORTED。scope 外既有 dirty 路径只要字节不变可保留为警告；任务新增的 scope 外变化是 FAILED。TaskGuard 不 stash、reset、stage、commit 或清理用户工作。

## Forbidden 与 surface

forbidden 项包含 `id/glob/regex/mode`：

- `eliminate`：当前必须零匹配；
- `no_new`：相对 init 的 path/line/digest 身份不得新增匹配。

surface 项包含 `id/argv/cwd/read_only/allowed_writes/normalizer_version`。`read_only` 只能为 `true`；normalizer 仅 `json-v1` 或 `text-v1`。命令失败、超时、输出截断、未知 normalizer、symlink 或未允许写入均不能产生 SUPPORTED。

初始化会把 `eliminate` 的正则与每个已归一化 surface 基线交叉检查。若待消除语义出现在冻结输出中，合同要求“删除”和“保持”同时成立，必须 fail closed；将 surface adapter 改成稳定字段投影，或收窄过宽的 forbidden 正则后重新初始化。原始 surface 输出不写入状态，只保存现有摘要。

接口精确性也属于 surface 合同：`json-v1` 会规范对象键顺序，但保留数组顺序、数组重复项和数值/字符串类型。除非需求明确声明无序，adapter 与 acceptance 都不得排序、去重或集合化；状态码、字段存在性和错误体形状也应直接纳入可观察证据。

## 状态语义

生命周期与 verdict 分离。required obligation 的聚合优先级为 `FAILED > STALE > UNKNOWN > SUPPORTED`；只有所有必需证据 SUPPORTED 才能进入 `TERMINAL/SUPPORTED`。`status` 是只读复验；`checkpoint` 单独保存恢复标签。中断的 RUNNING/RETRY_WAIT 不会隐式重放：先 status，随后用 `dispose --verdict UNKNOWN|FAILED` 保存处置，任务保持非成功终态。

Schema 能检查 JSON 类型、条件字段、受限枚举、完全重复项和可表达的词法路径；它不能证明路径当前不存在 symlink、repo 是真实 Git 根、nested repo/submodule 边界、regex 可执行、不同对象是否复用了同一 ID，或命令是否只读。这些都由 `validate_contract`、WorkspaceGuard 和实际命令运行时 fail closed 校验。
