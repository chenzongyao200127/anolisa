"""Unit tests for security_middleware.backends.hardening."""

import json
import subprocess
import unittest
from unittest.mock import patch

from agent_sec_cli.security_middleware.backends.hardening import (
    _MISSING_LOONGSHIELD_ERROR,
    HardeningBackend,
)
from agent_sec_cli.security_middleware.context import RequestContext


def _seharden_report(
    *,
    mode: str = "scan",
    returncode: int = 0,
    rules: list[dict] | None = None,
    summary: dict | None = None,
    config: str = "agentos_baseline",
    profile: str | None = "agentos_baseline",
    dry_run: bool = False,
    manual_review: list[dict] | None = None,
    available_levels: list[str] | None = None,
    error: str | None = None,
) -> str:
    rules = rules or []
    manual_review = manual_review or []
    summary = summary or {
        "passed": len([rule for rule in rules if rule.get("status") == "PASS"]),
        "fixed": len([rule for rule in rules if rule.get("status") == "FIXED"]),
        "failed": len(
            [
                rule
                for rule in rules
                if rule.get("status") not in {"PASS", "FIXED", "MANUAL", "DRY-RUN"}
            ]
        ),
        "manual": len([rule for rule in rules if rule.get("status") == "MANUAL"]),
        "dry_run_pending": len([rule for rule in rules if rule.get("status") == "DRY-RUN"]),
        "total": len(rules),
    }
    report = {
        "schema_version": 1,
        "format": "json",
        "tool": "loongshield",
        "command": "seharden",
        "status": "passed" if returncode == 0 else "failed",
        "mode": mode,
        "profile": profile,
        "level": "baseline",
        "dry_run": dry_run,
        "request": {
            "mode": mode,
            "config": config,
            "profile": profile,
            "level": "baseline",
            "requested_level": None,
            "dry_run": dry_run,
        },
        "rules": rules,
        "rule_count": len(rules),
        "summary": summary,
        "manual_review": manual_review,
        "manual_review_count": len(manual_review),
        "available_levels": available_levels,
        "exit_code": returncode,
        "error": error,
    }
    return json.dumps(report)


LOONGSHIELD_ALL_PASS_JSON = _seharden_report(
    rules=[
        {"id": "1.1.1", "desc": "Ensure mounting of cramfs is disabled", "status": "PASS"},
        {"id": "1.1.2", "desc": "Ensure mounting of squashfs is disabled", "status": "PASS"},
    ],
)

LOONGSHIELD_WITH_FAILURES_JSON = _seharden_report(
    returncode=1,
    rules=[
        {"id": "1.1.1", "desc": "Ensure cramfs disabled", "status": "PASS"},
        {
            "id": "fs.udf_disabled",
            "desc": "Ensure mounting of udf is disabled",
            "status": "FAIL",
            "reason": "udf module is loadable",
        },
        {
            "id": "time.sync_enabled",
            "desc": "Ensure time sync is enabled",
            "status": "FAIL",
            "reason": "chronyd is disabled",
        },
    ],
    manual_review=[
        {
            "area": "audit",
            "item": "Review audit policy exceptions.",
            "reason": "Audit policy evidence requires operator review.",
        }
    ],
)

LOONGSHIELD_REINFORCE_JSON = _seharden_report(
    mode="reinforce",
    returncode=1,
    rules=[
        {"id": "fs.udf_disabled", "desc": "Ensure udf disabled", "status": "FIXED"},
        {
            "id": "fs.shadow_perms",
            "desc": "Ensure shadow permissions",
            "status": "FAILED-TO-FIX",
            "reason": "Cannot set file permissions on /etc/shadow",
        },
        {
            "id": "kern.sysctl_apply",
            "desc": "Apply sysctl setting",
            "status": "ENFORCE-ERROR",
            "reason": "Failed to apply sysctl setting",
        },
    ],
)

LOONGSHIELD_DRYRUN_JSON = _seharden_report(
    mode="reinforce",
    returncode=1,
    dry_run=True,
    rules=[
        {
            "id": "fs.cramfs_blacklist",
            "desc": "Disable cramfs",
            "status": "DRY-RUN",
            "reason": "would apply cramfs blacklist",
        },
        {
            "id": "svc.chronyd_enable",
            "desc": "Enable chronyd",
            "status": "DRY-RUN",
            "reason": "would enable chronyd",
        },
    ],
)

LOONGSHIELD_ENGINE_ERROR_JSON = _seharden_report(
    returncode=1,
    rules=[
        {
            "id": "profile.load",
            "desc": "Profile load failed",
            "status": "ERROR",
            "reason": "config file not found: /etc/missing.conf",
        }
    ],
)

LOONGSHIELD_PROFILE_ERROR_JSON = _seharden_report(
    returncode=1,
    rules=[],
    profile="missing_profile",
    error="config file not found: /etc/missing.conf",
)


def _mock_proc(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["/usr/bin/loongshield", "seharden"],
        returncode=returncode,
        stdout=stdout,
    )


class TestBuildCommand(unittest.TestCase):
    def test_build_command_with_resolved_binary_forces_json(self):
        cmd = HardeningBackend._build_command(
            ["--scan", "--config", "agentos_baseline"],
            loongshield_path="/usr/bin/loongshield",
        )
        self.assertEqual(
            cmd,
            [
                "/usr/bin/loongshield",
                "seharden",
                "--scan",
                "--config",
                "agentos_baseline",
                "--format",
                "json",
            ],
        )

    def test_build_command_overrides_caller_format(self):
        cmd = HardeningBackend._build_command(
            ["--scan", "--format", "text", "--format=json"]
        )
        self.assertEqual(cmd, ["loongshield", "seharden", "--scan", "--format", "json"])

    def test_build_command_preserves_invalid_format_for_downstream_error(self):
        cmd = HardeningBackend._build_command(["--scan", "--format"])
        self.assertEqual(cmd, ["loongshield", "seharden", "--scan", "--format"])

    def test_build_command_keeps_help_text_passthrough(self):
        cmd = HardeningBackend._build_command(["--help"])
        self.assertEqual(cmd, ["loongshield", "seharden", "--help"])


class TestHardeningExecute(unittest.TestCase):
    def setUp(self):
        self.backend = HardeningBackend()
        self.ctx = RequestContext(action="harden")

    @patch("agent_sec_cli.security_middleware.backends.hardening.os.access")
    @patch("agent_sec_cli.security_middleware.backends.hardening.os.path.isfile")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_missing_loongshield_returns_clear_error(
        self, mock_which, mock_isfile, mock_access
    ):
        mock_which.return_value = None
        mock_isfile.return_value = False
        mock_access.return_value = False

        with self.assertLogs(
            "agent_sec_cli.security_middleware.backends.hardening", level="WARNING"
        ) as logs:
            result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 127)
        self.assertEqual(result.error, _MISSING_LOONGSHIELD_ERROR)
        self.assertEqual(
            result.data["argv"],
            ["loongshield", "seharden", "--scan", "--format", "json"],
        )
        self.assertEqual(result.data["failures"], [])
        self.assertEqual(result.data["fixed_items"], [])
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertEqual(record.levelname, "WARNING")
        self.assertEqual(record.trace_id, self.ctx.trace_id)
        self.assertEqual(record.data["action"], "harden")
        self.assertEqual(record.data["exit_code"], 127)
        self.assertEqual(record.data["error_type"], "FileNotFoundError")

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.os.access")
    @patch("agent_sec_cli.security_middleware.backends.hardening.os.path.isfile")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_falls_back_to_packaged_sbindir_binary(
        self, mock_which, mock_isfile, mock_access, mock_run
    ):
        mock_which.return_value = None
        mock_isfile.return_value = True
        mock_access.return_value = True
        mock_run.return_value = _mock_proc(LOONGSHIELD_ALL_PASS_JSON, 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        mock_run.assert_called_once_with(
            [
                "/usr/sbin/loongshield",
                "seharden",
                "--scan",
                "--format",
                "json",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["tool_path"], "/usr/sbin/loongshield")

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_no_args_preserve_legacy_default_scan_and_config(
        self, mock_which, mock_run
    ):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_ALL_PASS_JSON, 0)

        result = self.backend.execute(self.ctx)

        mock_run.assert_called_once_with(
            [
                "/usr/bin/loongshield",
                "seharden",
                "--scan",
                "--config",
                "agentos_baseline",
                "--format",
                "json",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data["mode"], "scan")
        self.assertEqual(result.data["config"], "agentos_baseline")
        self.assertEqual(result.data["loongshield_schema_version"], 1)
        self.assertIn("SEHarden scan", result.stdout)
        self.assertIn("2 passed", result.stdout)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_passthrough_args_force_json_and_parse_contract(
        self, mock_which, mock_run
    ):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_WITH_FAILURES_JSON, 1)

        result = self.backend.execute(
            self.ctx, args=["--scan", "--config", "agentos_baseline"]
        )

        mock_run.assert_called_once_with(
            [
                "/usr/bin/loongshield",
                "seharden",
                "--scan",
                "--config",
                "agentos_baseline",
                "--format",
                "json",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.data["passed"], 1)
        self.assertEqual(result.data["failed"], 2)
        self.assertEqual(result.data["manual"], 0)
        self.assertEqual(result.data["total"], 3)
        self.assertEqual(result.data["manual_review_count"], 1)
        self.assertEqual(result.data["manual_review"][0]["area"], "audit")
        self.assertIn("1 passed", result.stdout)
        self.assertIn("2 failed", result.stdout)
        self.assertEqual(len(result.data["failures"]), 2)
        self.assertEqual(result.data["fixed_items"], [])
        self.assertEqual(
            result.data["raw_args"], ["--scan", "--config", "agentos_baseline"]
        )

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_nonzero_exit_code_is_preserved(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_WITH_FAILURES_JSON, 3)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.data["returncode"], 3)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_legacy_mode_and_config_are_translated(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_REINFORCE_JSON, 1)

        result = self.backend.execute(
            self.ctx,
            mode="reinforce",
            config="agentos_baseline",
        )

        mock_run.assert_called_once_with(
            [
                "/usr/bin/loongshield",
                "seharden",
                "--reinforce",
                "--config",
                "agentos_baseline",
                "--format",
                "json",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(result.data["mode"], "reinforce")
        self.assertEqual(result.data["config"], "agentos_baseline")

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_reinforce_results_keep_failures_and_fixed_items(
        self, mock_which, mock_run
    ):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_REINFORCE_JSON, 1)

        result = self.backend.execute(
            self.ctx, args=["--reinforce", "--config", "agentos_baseline"]
        )

        self.assertEqual(result.data["fixed"], 1)
        self.assertEqual(len(result.data["fixed_items"]), 1)
        self.assertEqual(result.data["fixed_items"][0]["status"], "FIXED")
        statuses = [item["status"] for item in result.data["failures"]]
        self.assertIn("FAILED-TO-FIX", statuses)
        self.assertIn("ENFORCE-ERROR", statuses)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_dry_run_entries_are_reported(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_DRYRUN_JSON, 1)

        result = self.backend.execute(
            self.ctx, args=["--reinforce", "--dry-run", "--config", "agentos_baseline"]
        )

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.data["mode"], "reinforce")
        self.assertTrue(result.data["dry_run"])
        self.assertEqual(result.data["dry_run_pending"], 2)
        self.assertIn("SEHarden reinforce (dry-run)", result.stdout)
        statuses = [item["status"] for item in result.data["failures"]]
        self.assertIn("DRY-RUN", statuses)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_dry_run_mode_detection_is_order_independent(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_DRYRUN_JSON, 1)

        result = self.backend.execute(
            self.ctx, args=["--dry-run", "--reinforce", "--config", "agentos_baseline"]
        )

        self.assertEqual(result.data["mode"], "reinforce")
        self.assertTrue(result.data["dry_run"])

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_engine_error_is_kept_in_failures(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_ENGINE_ERROR_JSON, 1)

        result = self.backend.execute(self.ctx, args=["--scan"])

        engine_errors = [
            item for item in result.data["failures"] if item["status"] == "ERROR"
        ]
        self.assertEqual(len(engine_errors), 1)
        self.assertIn("config file not found", engine_errors[0]["message"])

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_top_level_error_is_preserved(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_PROFILE_ERROR_JSON, 1)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertEqual(
            result.data["error"], "config file not found: /etc/missing.conf"
        )
        self.assertIn("Error: config file not found", result.stdout)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_verbose_output_is_synthesized_from_json(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(LOONGSHIELD_WITH_FAILURES_JSON, 1)

        result = self.backend.execute(self.ctx, args=["--scan", "--verbose"])

        self.assertIn("Rules:", result.stdout)
        self.assertIn("FAIL [fs.udf_disabled] Ensure mounting of udf is disabled", result.stdout)
        self.assertIn("reason: udf module is loadable", result.stdout)
        self.assertIn("Manual Review Summary: 1 item(s)", result.stdout)
        self.assertIn("[audit] Review audit policy exceptions.", result.stdout)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_help_text_passthrough_is_not_parsed_as_json(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc("seharden help\n", 0)

        result = self.backend.execute(self.ctx, args=["--help"])

        mock_run.assert_called_once_with(
            [
                "/usr/bin/loongshield",
                "seharden",
                "--help",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertTrue(result.success)
        self.assertNotIn("passed", result.data)
        self.assertNotIn("loongshield_schema_version", result.data)
        self.assertEqual(result.stdout, "seharden help\n")

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_text_output_is_not_parsed_as_fallback(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.return_value = _mock_proc(
            "SEHarden Finished. 23 passed, 0 fixed, 0 failed, "
            "0 manual, 0 dry-run-pending / 23 total.\n",
            0,
        )

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("did not return valid JSON", result.error)
        self.assertNotIn("passed", result.data)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_json_contract_violation_fails_closed(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        bad_report["schema_version"] = 2
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("JSON contract violation", result.error)
        self.assertIn("schema_version", result.error)
        self.assertEqual(result.data["error"], result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_summary_counts_are_required_in_json_contract(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        del bad_report["summary"]["passed"]
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("summary.passed is not an integer", result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_rule_items_must_be_json_objects(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        bad_report["rules"] = ["not-an-object"]
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("rules contains a non-object item", result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_rule_items_must_include_required_fields(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        del bad_report["rules"][0]["id"]
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("rules[1].id must be a non-empty string", result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_rule_count_must_match_rules_length(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        bad_report["rule_count"] = 23
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("rule_count does not match rules length", result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_summary_must_match_rule_statuses(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_ALL_PASS_JSON)
        bad_report["summary"]["passed"] = 1
        bad_report["summary"]["failed"] = 1
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 0)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("summary.passed does not match rules statuses", result.error)

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_manual_review_count_must_match_manual_review_length(
        self, mock_which, mock_run
    ):
        mock_which.return_value = "/usr/bin/loongshield"
        bad_report = json.loads(LOONGSHIELD_WITH_FAILURES_JSON)
        bad_report["manual_review_count"] = 2
        mock_run.return_value = _mock_proc(json.dumps(bad_report), 1)

        result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn(
            "manual_review_count does not match manual_review length", result.error
        )

    @patch("agent_sec_cli.security_middleware.backends.hardening.subprocess.run")
    @patch("agent_sec_cli.security_middleware.backends.hardening.shutil.which")
    def test_oserror_is_reported_clearly(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/loongshield"
        mock_run.side_effect = OSError("Permission denied")

        with self.assertLogs(
            "agent_sec_cli.security_middleware.backends.hardening", level="ERROR"
        ) as logs:
            result = self.backend.execute(self.ctx, args=["--scan"])

        self.assertFalse(result.success)
        self.assertIn("Failed to execute `loongshield seharden`", result.error)
        self.assertIn("Permission denied", result.error)
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertEqual(record.levelname, "ERROR")
        self.assertEqual(record.trace_id, self.ctx.trace_id)
        self.assertEqual(record.data["action"], "harden")
        self.assertEqual(record.data["exit_code"], 1)
        self.assertIsNotNone(record.exc_info)
        self.assertIs(record.exc_info[0], OSError)

    def test_unknown_legacy_kwargs_are_rejected(self):
        with self.assertRaises(TypeError):
            self.backend.execute(self.ctx, profile="agentos_baseline")

    def test_mixing_args_and_legacy_kwargs_is_rejected(self):
        with self.assertRaises(TypeError):
            self.backend.execute(
                self.ctx,
                args=["--scan"],
                mode="reinforce",
            )


if __name__ == "__main__":
    unittest.main()
