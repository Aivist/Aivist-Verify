---
name: backend-testing
description: 在 Anti-Gravity 项目运行 Python 后端 pytest 测试的标准方式。涉及跑测试、验证 pruner/fuzzer、pytest 导入报错 (ModuleNotFoundError backend.app) 时使用。
---

# 后端测试运行规范

## 关键点

测试用 `from backend.app...` 绝对导入，**必须从仓库根目录运行**，否则 `backend` 包无法解析。

- 仓库根：`c:\Users\Lang\Desktop\anti gravity`
- 测试位置：`backend/tests/`（如 `test_pruner.py`）

## 运行命令

从仓库根执行：

```bash
python -m pytest backend/tests -v
```

跑单个文件：

```bash
python -m pytest backend/tests/test_pruner.py -v
```

## 环境注意

- Agent 的 Shell 跑在 **Windows PowerShell 5.1**：串联命令用 `;`，**不要用 `&&`**。
- 路径含空格（`anti gravity`），如需 `cd` 必须加引号。
- 异步测试需 `pytest-asyncio`；若测 `fuzzer.py` 等 async 代码报 "async def not natively supported"，先确认它已装并在测试加 `@pytest.mark.asyncio`。
