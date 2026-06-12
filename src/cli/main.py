"""CLI 入口 — crash-ai analyze 命令。

提供了 crash-ai 命令行工具的 analyze 子命令, 包含符号解析、
AI 分析(可选)、多种输出格式和 dry-run 模式。
"""
import sys
import json
import asyncio
import click
from pathlib import Path
from src.config import Config
from src.input.format_detector import detect_format
from src.input.elf_reader import ELFReader
from src.symbol.resolver import SymbolResolver
from src.analysis.engine import AnalysisEngine
from src.output.json_formatter import format_json
from src.output.terminal import format_terminal
from src.output.markdown_formatter import format_markdown
from src.analysis.prompts.user import build_user_prompt
from src.analysis.prompts.system import SYSTEM_PROMPT
from src.errors import (
    CrashAIError, InputError, ConfigError, NetworkError, AnalysisIncompleteError
)

# 退出码映射
EXIT_SUCCESS = 0
EXIT_INCOMPLETE = 1
EXIT_INPUT_ERROR = 2
EXIT_CONFIG_ERROR = 3
EXIT_NETWORK_ERROR = 4
EXIT_INTERNAL_ERROR = 5


def _run_async(coro):
    """Helper to run async functions from sync click commands."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio  # type: ignore[import-untyped]
            nest_asyncio.apply()
            return loop.run_until_complete(coro)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


@click.group()
def cli():
    """Crash AI — AI 驱动的 Core Dump 分析系统。"""
    pass


@cli.command()
@click.argument("core_dump", type=click.Path(exists=True))
@click.option("--source", type=click.Path(exists=True), help="源代码根目录")
@click.option("--symbols", type=click.Path(exists=True), help="调试符号目录")
@click.option("--output", type=click.Path(), help="输出报告路径 (默认 stdout)")
@click.option("--format", "fmt", type=click.Choice(["json", "text", "markdown"]), default="json", help="输出格式")
@click.option("--provider", type=click.Choice(["deepseek", "anthropic"]), help="LLM provider")
@click.option("--platform", type=click.Choice(["auto", "linux", "macos"]), default="auto", help="目标平台")
@click.option("--no-ai", is_flag=True, help="仅符号解析, 不调 LLM")
@click.option("--dry-run", is_flag=True, help="展示 Prompt 内容, 不实际调用 LLM")
@click.option("--timeout", type=int, default=30, help="GDB subprocess 超时(秒)")
def analyze(core_dump, source, symbols, output, fmt, provider, platform, no_ai, dry_run, timeout):
    """分析 core dump 文件并生成崩溃报告。"""
    try:
        core_path = Path(core_dump)

        # 1. Format detection
        file_format = detect_format(core_path)

        # 2. Input parsing (Phase 1: header validation only)
        if file_format == "elf":
            reader = ELFReader(core_path)
            # ELFReader.read() is not called in Phase 1 — full context via GDB
        else:
            raise InputError(f"Unsupported format: {file_format}")

        # 3. Symbol resolution
        resolver = SymbolResolver()
        # Create minimal CrashContext from ELF header
        from datetime import datetime
        from src.models.crash import CrashContext, CrashMetadata

        meta = CrashMetadata(
            timestamp=datetime.now(), hostname="unknown", kernel_version="unknown",
            distribution="unknown", arch="unknown", coredump_size_bytes=core_path.stat().st_size,
        )
        crash_ctx = CrashContext(
            signal="SIGSEGV", fault_addr="0x0",
            thread_states=[], registers={}, raw_stack=[],
            memory_maps=[], loaded_modules=[], metadata=meta,
        )
        resolved_ctx = resolver.resolve(
            core_path=core_path,
            crash_ctx=crash_ctx,
            symbol_dir=Path(symbols) if symbols else None,
        )

        # 4. AI Analysis (optional)
        if no_ai:
            formatted = _build_no_ai_output(resolved_ctx)
        elif dry_run:
            prompt = build_user_prompt(resolved_ctx)
            formatted = f"=== SYSTEM PROMPT ===\n{SYSTEM_PROMPT}\n\n=== USER PROMPT ===\n{prompt}"
        else:
            config = Config()
            engine = AnalysisEngine(config, provider=provider)
            report = _run_async(engine.analyze(resolved_ctx))

            if fmt == "json":
                formatted = format_json(report)
            elif fmt == "markdown":
                formatted = format_markdown(report)
            else:
                formatted = format_terminal(report)

        # 5. Output
        if output:
            Path(output).write_text(formatted)
            click.echo(f"Report written to {output}")
        else:
            click.echo(formatted)

    except InputError as e:
        click.echo(f"输入错误: {e}", err=True)
        sys.exit(EXIT_INPUT_ERROR)
    except ConfigError as e:
        click.echo(f"配置错误: {e}", err=True)
        sys.exit(EXIT_CONFIG_ERROR)
    except NetworkError as e:
        click.echo(f"网络错误: {e}", err=True)
        sys.exit(EXIT_NETWORK_ERROR)
    except AnalysisIncompleteError as e:
        click.echo(f"分析不完整: {e}", err=True)
        sys.exit(EXIT_INCOMPLETE)
    except CrashAIError as e:
        click.echo(f"内部错误: {e}", err=True)
        sys.exit(EXIT_INTERNAL_ERROR)


def _build_no_ai_output(resolved_ctx):
    """构建 --no-ai 模式下的符号解析输出。"""
    report_data = {
        "mode": "no-ai",
        "signal": resolved_ctx.signal_analysis,
        "crash_thread": {
            "tid": resolved_ctx.crash_thread.tid,
            "lwpid": resolved_ctx.crash_thread.lwpid,
        },
        "resolved_frames": [
            {
                "frame_num": f.frame_num,
                "function": f.function,
                "source_file": f.source_file,
                "source_line": f.source_line,
            }
            for f in resolved_ctx.resolved_stack[:50]
        ],
        "registers": resolved_ctx.crash_thread.registers_at_crash,
    }
    return json.dumps(report_data, indent=2, default=str)
