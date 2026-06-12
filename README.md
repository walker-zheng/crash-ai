# crash-ai

AI 驱动的 C/C++ crash 深度根因分析 CLI 工具。把十年 crash 分析经验封装为一行命令。

**当前状态**: Phase 1 设计阶段，即将开始编码。

## 一句话

```
crash-ai core.core --symbols ./lib.rpm --source ./src:commit=abc1234
```

## 架构

10 步分析 Pipeline: 输入 → 符号解析 → 源码提取 → Git 信息采集 → 多源交叉验证 → AI 5步推理链 → 输出报告

## 快速开始

```bash
# 安装 (待 Phase 1 实现)
pip install crash-ai

# 基础用法
crash-ai core.core --symbols ./lib.rpm --source ./src

# 指定源码版本
crash-ai core.core --symbols ./lib.rpm --source ./src:commit=abc1234

# 输出 JSON 报告
crash-ai core.core --symbols ./lib.rpm --source ./src --json

# 纯符号解析 (不调 AI)
crash-ai core.core --symbols ./lib.rpm --no-ai
```

## 项目结构

```
crash-ai/
├── src/       # 源代码
├── tests/     # 单元测试
├── examples/  # 公开 crash 样本
└── data/      # 运行时数据 (.gitignored)
```

## 核心能力

- **自动符号解析**: 从 RPM/DEB/dSYM 提取调试符号，匹配崩溃地址
- **源码自动提取**: 通过 Git commit 精确定位崩溃版本源码
- **多源交叉验证**: 堆栈、寄存器、源码、系统日志交叉验证
- **AI 5步推理链**: 寄存器判读 → 堆栈重建 → 日志关联 → 代码审查 → 综合判断
- **结构化报告**: JSON/Markdown 双格式输出，含证据链和置信度

## 技术栈

Python 3.10+ · GDB/LLDB · Anthropic/DeepSeek API · Rich 终端 UI

## License

MIT
