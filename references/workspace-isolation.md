# 工作区隔离守卫

当任务涉及临时克隆、worktree、多个同名仓库或必须保护的原仓库时使用。此守卫解决“shell 在克隆中，但写工具按其他根解析路径”的问题；状态文件必须放在产品仓库之外的临时目录。

```bash
python3 "$ligong_skill_root/scripts/workspace_guard.py" bind \
  --workspace "$worker_repo" --protect "$source_repo" --state "$guard_state"
python3 "$ligong_skill_root/scripts/workspace_guard.py" assert-path \
  --state "$guard_state" --path "$target_path"
python3 "$ligong_skill_root/scripts/workspace_guard.py" check --state "$guard_state"
```

规则：

- `bind` 前分别以 `git rev-parse --show-toplevel` 解析唯一工作区和所有受保护仓库；不得用相对路径、目录名猜测或仅相信 shell `cwd`。
- 每批写入前，对所有目标运行 `assert-path`；目标必须解析到绑定工作区以内。`apply_patch` 等没有独立工作目录参数的工具也不能例外。
- 每批写入后、worker 返回前和主 Agent 最终验收前运行 `check`。受保护仓库的 HEAD 或 tracked/untracked dirty 指纹变化即 `VIOLATION`，立即停止并报告。
- 守卫只验证按协议提交的目标路径并侦测 Git 可见污染，不能拦截绕过守卫的任意文件系统写入，也不覆盖 ignored 文件。工具平台若提供强制 filesystem sandbox/allowlist，应优先启用，并把本守卫作为第二层证据。
