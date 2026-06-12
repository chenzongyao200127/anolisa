"""Hardening backend — JSON-contract wrapper for `loongshield seharden`.

The backend preserves the wrapper's legacy defaults and structured event data
while forcing the downstream machine-readable JSON contract for hardening runs.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any

from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult

DEFAULT_HARDEN_CONFIG = "agentos_baseline"
_DEFAULT_HARDEN_MODE = "scan"
_FALLBACK_LOONGSHIELD_PATHS = ("/usr/sbin/loongshield",)
_MISSING_LOONGSHIELD_ERROR = (
    "The `loongshield` command is required for `agent-sec-cli harden`, "
    "but it was not found.\n"
    "On ALinux 4 Operating System, you can usually install it from the default yum "
    "repository with:\n"
    "  sudo yum install -y loongshield\n"
    "If it is already installed, please make sure the `loongshield` binary is "
    "available in PATH."
)
logger = logging.getLogger(__name__)

_LOONGSHIELD_JSON_SCHEMA_VERSION = 1
_PASS_STATUSES = frozenset({"PASS", "FIXED"})
_VALID_RULE_STATUSES = frozenset(
    {
        "PASS",
        "FAIL",
        "ERROR",
        "FIXED",
        "FAILED-TO-FIX",
        "ENFORCE-ERROR",
        "MANUAL",
        "DRY-RUN",
    }
)
_REQUIRED_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "format",
        "tool",
        "command",
        "status",
        "mode",
        "profile",
        "level",
        "dry_run",
        "request",
        "rules",
        "rule_count",
        "summary",
        "manual_review",
        "manual_review_count",
        "available_levels",
        "exit_code",
        "error",
    }
)
_REQUIRED_REQUEST_FIELDS = frozenset(
    {"mode", "config", "profile", "level", "requested_level", "dry_run"}
)


class HardeningBackend(BaseBackend):
    """Execute `loongshield seharden` and keep structured hardening results."""

    def execute(
        self,
        ctx: RequestContext,
        args: list[str] | tuple[str, ...] | None = None,
        **kwargs: Any,
    ) -> ActionResult:
        """Execute `loongshield seharden` with raw args or legacy kwargs."""
        raw_args = self._normalize_args(args=args, **kwargs)
        mode, config = self._describe_request(raw_args)
        loongshield_path = self._resolve_loongshield_path()
        cmd = self._build_command(raw_args, loongshield_path=loongshield_path)
        data = self._build_result_data(
            raw_args=raw_args,
            cmd=cmd,
            tool_path=loongshield_path,
            mode=mode,
            config=config,
        )

        if not loongshield_path:
            logger.warning(
                "loongshield command not found",
                extra={
                    "trace_id": ctx.trace_id,
                    "data": {
                        "action": ctx.action,
                        "caller": ctx.caller,
                        "exit_code": 127,
                        "error_type": "FileNotFoundError",
                    },
                },
            )
            return ActionResult(
                success=False,
                exit_code=127,
                error=_MISSING_LOONGSHIELD_ERROR,
                data=data,
            )

        try:
            proc = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            exit_code = getattr(exc, "errno", 1) or 1
            logger.error(
                "failed to execute loongshield seharden",
                exc_info=True,
                extra={
                    "trace_id": ctx.trace_id,
                    "data": {
                        "action": ctx.action,
                        "caller": ctx.caller,
                        "exit_code": exit_code,
                    },
                },
            )
            return ActionResult(
                success=False,
                exit_code=exit_code,
                error=f"Failed to execute `loongshield seharden`: {exc}",
                data=data,
            )

        clean_output = proc.stdout or ""
        data["returncode"] = proc.returncode
        parse_error, report = self._parse_json_output(clean_output, data)
        if parse_error:
            data["error"] = parse_error
        exit_code = proc.returncode if proc.returncode != 0 or not parse_error else 1
        stdout = clean_output if _is_help_request(raw_args) else ""
        if report is not None:
            if "--verbose" in raw_args:
                stdout = _format_json_stdout_verbose(report)
            else:
                stdout = _format_json_stdout(report)

        return ActionResult(
            success=(proc.returncode == 0 and parse_error is None),
            stdout=stdout,
            exit_code=exit_code,
            error=parse_error or "",
            data=data,
        )

    @classmethod
    def _normalize_args(
        cls,
        args: list[str] | tuple[str, ...] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        raw_args = [str(arg) for arg in (args or [])]
        if raw_args and kwargs:
            mixed_keys = ", ".join(sorted(kwargs))
            raise TypeError(f"Do not mix passthrough args with legacy harden kwargs: {mixed_keys}")

        if raw_args:
            return raw_args

        legacy_keys = {"mode", "config"}
        unknown_keys = sorted(set(kwargs) - legacy_keys)
        if unknown_keys:
            unknown = ", ".join(unknown_keys)
            raise TypeError(f"Unsupported harden kwargs: {unknown}")

        if not kwargs:
            return cls._legacy_args(
                mode=_DEFAULT_HARDEN_MODE,
                config=DEFAULT_HARDEN_CONFIG,
            )

        mode = str(kwargs.get("mode", _DEFAULT_HARDEN_MODE))
        config = str(kwargs.get("config", DEFAULT_HARDEN_CONFIG))
        return cls._legacy_args(mode=mode, config=config)

    @staticmethod
    def _legacy_args(mode: str, config: str) -> list[str]:
        if mode == "dry-run":
            return ["--reinforce", "--dry-run", "--config", config]
        if mode == "reinforce":
            return ["--reinforce", "--config", config]
        if mode == "scan":
            return ["--scan", "--config", config]
        raise ValueError(f"Invalid harden mode '{mode}'. Choose from: scan, reinforce, dry-run")

    @staticmethod
    def _describe_request(args: list[str]) -> tuple[str | None, str | None]:
        mode: str | None = None
        config: str | None = None
        has_scan = "--scan" in args
        has_reinforce = "--reinforce" in args
        has_dry_run = "--dry-run" in args

        if has_reinforce or has_dry_run:
            mode = "reinforce"
        if has_scan:
            mode = "scan"

        for index, arg in enumerate(args):
            if arg == "--config" and index + 1 < len(args):
                config = args[index + 1]
            elif arg.startswith("--config="):
                config = arg.split("=", 1)[1]

        return mode, config

    @staticmethod
    def _build_command(
        args: list[str] | tuple[str, ...], loongshield_path: str | None = None
    ) -> list[str]:
        raw_args = list(args)
        if _is_help_request(raw_args):
            seharden_args = raw_args
        else:
            seharden_args = _ensure_json_format_args(raw_args)
        return [loongshield_path or "loongshield", "seharden", *seharden_args]

    @staticmethod
    def _build_result_data(
        raw_args: list[str],
        cmd: list[str],
        tool_path: str | None,
        mode: str | None,
        config: str | None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "argv": cmd,
            "raw_args": raw_args,
            "tool_path": tool_path,
            "failures": [],
            "fixed_items": [],
        }
        if mode is not None:
            data["mode"] = mode
        if config is not None:
            data["config"] = config
        return data

    @staticmethod
    def _resolve_loongshield_path() -> str | None:
        resolved = shutil.which("loongshield")
        if resolved:
            return resolved

        for candidate in _FALLBACK_LOONGSHIELD_PATHS:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    @classmethod
    def _parse_json_output(
        cls, clean_output: str, data: dict[str, Any]
    ) -> tuple[str | None, dict[str, Any] | None]:
        if _is_help_request(data["raw_args"]):
            return None, None

        try:
            report = json.loads(clean_output)
        except json.JSONDecodeError as exc:
            return f"loongshield seharden did not return valid JSON: {exc.msg}", None

        contract_error = cls._validate_json_contract(report)
        if contract_error:
            return contract_error, None

        summary = report["summary"]
        rules = report["rules"]
        data["loongshield_schema_version"] = report["schema_version"]
        data["loongshield_status"] = report.get("status")
        data["summary"] = summary
        data["mode"] = report.get("mode")
        data["dry_run"] = report.get("dry_run")
        data["config"] = (report.get("request") or {}).get("config")
        data["passed"] = _as_int(summary.get("passed"))
        data["fixed"] = _as_int(summary.get("fixed"))
        data["failed"] = _as_int(summary.get("failed"))
        data["manual"] = _as_int(summary.get("manual"))
        data["dry_run_pending"] = _as_int(summary.get("dry_run_pending"))
        data["total"] = _as_int(summary.get("total"), _as_int(report.get("rule_count")))
        data["failures"] = [
            _rule_entry(rule)
            for rule in rules
            if str(rule.get("status", "UNKNOWN")) not in _PASS_STATUSES
        ]
        data["fixed_items"] = [
            _rule_entry(rule) for rule in rules if str(rule.get("status")) == "FIXED"
        ]
        data["manual_review"] = report["manual_review"]
        data["manual_review_count"] = report["manual_review_count"]
        data["available_levels"] = report["available_levels"]

        if report.get("error"):
            data["error"] = report["error"]

        reported_nonpass = data["failed"] + data["manual"] + data["dry_run_pending"]
        if reported_nonpass > 0 and not data["failures"]:
            data["failures"].append(
                {
                    "rule_id": "",
                    "status": "UNKNOWN",
                    "message": (
                        f"JSON summary reports {reported_nonpass} non-pass rule(s) "
                        "but the rules array contains no matching details."
                    ),
                }
            )
        return None, report

    @staticmethod
    def _validate_json_contract(report: Any) -> str | None:
        if not isinstance(report, dict):
            return "loongshield seharden JSON contract violation: top-level value is not an object"
        missing_fields = _REQUIRED_TOP_LEVEL_FIELDS - report.keys()
        if missing_fields:
            return (
                "loongshield seharden JSON contract violation: "
                f"missing top-level field {sorted(missing_fields)[0]!r}"
            )
        expected = {
            "schema_version": _LOONGSHIELD_JSON_SCHEMA_VERSION,
            "format": "json",
            "tool": "loongshield",
            "command": "seharden",
        }
        for key, value in expected.items():
            if report.get(key) != value:
                return (
                    "loongshield seharden JSON contract violation: "
                    f"expected {key}={value!r}, got {report.get(key)!r}"
                )
        if not isinstance(report.get("request"), dict):
            return "loongshield seharden JSON contract violation: request is not an object"
        missing_request_fields = _REQUIRED_REQUEST_FIELDS - report["request"].keys()
        if missing_request_fields:
            return (
                "loongshield seharden JSON contract violation: "
                f"missing request field {sorted(missing_request_fields)[0]!r}"
            )
        if not isinstance(report.get("summary"), dict):
            return "loongshield seharden JSON contract violation: summary is not an object"
        scalar_error = _validate_scalar_fields(report)
        if scalar_error:
            return scalar_error
        if not isinstance(report.get("rules"), list):
            return "loongshield seharden JSON contract violation: rules is not an array"
        rule_error = _validate_rules(report["rules"])
        if rule_error:
            return rule_error
        if not isinstance(report.get("manual_review"), list):
            return "loongshield seharden JSON contract violation: manual_review is not an array"
        if len(report["rules"]) != report["rule_count"]:
            return (
                "loongshield seharden JSON contract violation: "
                "rule_count does not match rules length"
            )
        if len(report["manual_review"]) != report["manual_review_count"]:
            return (
                "loongshield seharden JSON contract violation: "
                "manual_review_count does not match manual_review length"
            )
        summary_error = _validate_summary(report["summary"], report["rule_count"])
        if summary_error:
            return summary_error
        status_count_error = _validate_summary_matches_rules(
            report["summary"], report["rules"]
        )
        if status_count_error:
            return status_count_error
        return None


def _is_help_request(args: list[str]) -> bool:
    return "--help" in args or "-h" in args


def _validate_scalar_fields(report: dict[str, Any]) -> str | None:
    expected_strings = {
        "status": {"passed", "failed"},
        "mode": {"scan", "reinforce"},
    }
    for key, allowed_values in expected_strings.items():
        value = report.get(key)
        if not isinstance(value, str) or value not in allowed_values:
            return (
                "loongshield seharden JSON contract violation: "
                f"{key} must be one of {sorted(allowed_values)!r}"
            )

    if not isinstance(report.get("dry_run"), bool):
        return "loongshield seharden JSON contract violation: dry_run is not a boolean"

    for key in ("rule_count", "manual_review_count", "exit_code"):
        if type(report.get(key)) is not int:
            return (
                "loongshield seharden JSON contract violation: "
                f"{key} is not an integer"
            )

    if report["status"] != ("passed" if report["exit_code"] == 0 else "failed"):
        return (
            "loongshield seharden JSON contract violation: "
            "status does not match exit_code"
        )

    if report["request"].get("mode") != report["mode"]:
        return (
            "loongshield seharden JSON contract violation: "
            "request.mode does not match mode"
        )
    if report["request"].get("dry_run") is not report["dry_run"]:
        return (
            "loongshield seharden JSON contract violation: "
            "request.dry_run does not match dry_run"
        )
    if not isinstance(report.get("level"), str) or report["level"] == "":
        return "loongshield seharden JSON contract violation: level must be a non-empty string"
    if not isinstance(report["request"].get("level"), str) or report["request"]["level"] == "":
        return (
            "loongshield seharden JSON contract violation: "
            "request.level must be a non-empty string"
        )
    for key in ("profile", "error"):
        value = report.get(key)
        if value is not None and not isinstance(value, str):
            return (
                "loongshield seharden JSON contract violation: "
                f"{key} must be a string or null"
            )
    for key in ("config", "profile", "requested_level"):
        value = report["request"].get(key)
        if value is not None and not isinstance(value, str):
            return (
                "loongshield seharden JSON contract violation: "
                f"request.{key} must be a string or null"
            )

    available_levels = report.get("available_levels")
    if available_levels is not None and not (
        isinstance(available_levels, list)
        and all(isinstance(item, str) for item in available_levels)
    ):
        return (
            "loongshield seharden JSON contract violation: "
            "available_levels must be an array of strings or null"
        )
    return None


def _validate_summary(summary: dict[str, Any], rule_count: int) -> str | None:
    summary_keys = ("passed", "fixed", "failed", "manual", "dry_run_pending", "total")
    for key in summary_keys:
        value = summary.get(key)
        if type(value) is not int:
            return (
                "loongshield seharden JSON contract violation: "
                f"summary.{key} is not an integer"
            )
    if summary["total"] != rule_count:
        return (
            "loongshield seharden JSON contract violation: "
            "summary.total does not match rule_count"
        )
    counted = (
        summary["passed"]
        + summary["fixed"]
        + summary["failed"]
        + summary["manual"]
        + summary["dry_run_pending"]
    )
    if counted != summary["total"]:
        return (
            "loongshield seharden JSON contract violation: "
            "summary counts do not add up to summary.total"
        )
    return None


def _validate_summary_matches_rules(
    summary: dict[str, Any], rules: list[dict[str, Any]]
) -> str | None:
    counts = {
        "passed": 0,
        "fixed": 0,
        "failed": 0,
        "manual": 0,
        "dry_run_pending": 0,
    }
    for rule in rules:
        status = rule["status"]
        if status == "PASS":
            counts["passed"] += 1
        elif status == "FIXED":
            counts["fixed"] += 1
        elif status == "MANUAL":
            counts["manual"] += 1
        elif status == "DRY-RUN":
            counts["dry_run_pending"] += 1
        else:
            counts["failed"] += 1

    for key, value in counts.items():
        if summary[key] != value:
            return (
                "loongshield seharden JSON contract violation: "
                f"summary.{key} does not match rules statuses"
            )
    return None


def _validate_rules(rules: list[Any]) -> str | None:
    required_strings = ("id", "desc", "status")
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            return "loongshield seharden JSON contract violation: rules contains a non-object item"
        for key in required_strings:
            value = rule.get(key)
            if not isinstance(value, str) or value == "":
                return (
                    "loongshield seharden JSON contract violation: "
                    f"rules[{index}].{key} must be a non-empty string"
                )
        if rule["status"] not in _VALID_RULE_STATUSES:
            return (
                "loongshield seharden JSON contract violation: "
                f"rules[{index}].status is not a known v1 status"
            )
        reason = rule.get("reason")
        if reason is not None and not isinstance(reason, str):
            return (
                "loongshield seharden JSON contract violation: "
                f"rules[{index}].reason must be a string or null"
            )
    return None


def _ensure_json_format_args(args: list[str]) -> list[str]:
    normalized: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--format":
            if index + 1 < len(args) and args[index + 1] in {"text", "json"}:
                index += 2
                continue
            return list(args)
        if arg.startswith("--format="):
            if arg.split("=", 1)[1] in {"text", "json"}:
                index += 1
                continue
            return list(args)
        normalized.append(arg)
        index += 1
    normalized.extend(["--format", "json"])
    return normalized


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _rule_entry(rule: dict[str, Any]) -> dict[str, str]:
    return {
        "rule_id": str(rule.get("id") or ""),
        "status": str(rule.get("status") or "UNKNOWN"),
        "message": str(rule.get("reason") or rule.get("desc") or ""),
    }


def _format_json_stdout(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    profile = report.get("profile") or (report.get("request") or {}).get("config")
    mode = report.get("mode") or "scan"
    mode_label = f"{mode} (dry-run)" if report.get("dry_run") else mode
    level = report.get("level") or "all"
    total = _as_int(summary.get("total"), _as_int(report.get("rule_count")))
    lines = [
        f"SEHarden {mode_label}: profile='{profile}', level='{level}', {total} rule(s)",
        (
            "SEHarden Finished. "
            f"{_as_int(summary.get('passed'))} passed, "
            f"{_as_int(summary.get('fixed'))} fixed, "
            f"{_as_int(summary.get('failed'))} failed, "
            f"{_as_int(summary.get('manual'))} manual, "
            f"{_as_int(summary.get('dry_run_pending'))} dry-run-pending / "
            f"{total} total."
        ),
    ]
    if report.get("error"):
        lines.append(f"Error: {report['error']}")
    return "\n".join(lines) + "\n"


def _format_json_stdout_verbose(report: dict[str, Any]) -> str:
    lines = [_format_json_stdout(report).rstrip()]
    rules = report.get("rules") or []
    if rules:
        lines.append("")
        lines.append("Rules:")
        for rule in rules:
            reason = rule.get("reason")
            desc = rule.get("desc") or ""
            lines.append(f"  {rule.get('status')} [{rule.get('id')}] {desc}")
            if reason:
                lines.append(f"    reason: {reason}")

    manual_review = report.get("manual_review") or []
    if manual_review:
        lines.append("")
        lines.append(f"Manual Review Summary: {len(manual_review)} item(s)")
        for item in manual_review:
            area = item.get("area", "")
            text = item.get("item", "")
            reason = item.get("reason")
            lines.append(f"  - [{area}] {text}")
            if reason:
                lines.append(f"    reason: {reason}")

    return "\n".join(lines) + "\n"
