"""Unit tests for the top-level CLI entry points."""

import unittest
from unittest.mock import patch

from agent_sec_cli.cli import app
from agent_sec_cli.security_middleware.result import ActionResult
from typer.testing import CliRunner


class TestHardenCli(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_harden_help_shows_concise_summary(self):
        result = self.runner.invoke(app, ["harden", "--help"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage: agent-sec-cli harden [SEHARDEN_ARGS]...", result.output)
        self.assertIn("Defaults:", result.output)
        self.assertIn("--scan --config agentos_baseline", result.output)
        self.assertIn("Examples:", result.output)
        self.assertIn("Common SEHarden flags:", result.output)
        self.assertIn("--downstream-help", result.output)
        self.assertNotIn(
            "Pass arguments through to `loongshield seharden`.", result.output
        )
        self.assertNotIn("-- --help", result.output)

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_adds_default_scan_and_config_on_zero_args(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(app, ["harden"])

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--config", "agentos_baseline"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_forwards_unknown_args_to_backend(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(
            app,
            ["harden", "--scan", "--config", "agentos_baseline", "--dry-run"],
        )

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--config", "agentos_baseline", "--dry-run"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_adds_default_config_when_missing(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(app, ["harden", "--scan"])

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--config", "agentos_baseline"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_adds_default_scan_when_only_config_is_provided(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(app, ["harden", "--config", "custom_profile"])

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--config", "custom_profile"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_keeps_explicit_equals_style_config(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(
            app, ["harden", "--scan", "--config=custom_profile"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--config=custom_profile"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_does_not_add_default_scan_for_reinforce(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(app, ["harden", "--reinforce", "--dry-run"])

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--reinforce", "--dry-run", "--config", "agentos_baseline"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_keeps_explicit_verbose(self, mock_invoke):
        mock_invoke.return_value = ActionResult(success=True, exit_code=0)

        result = self.runner.invoke(app, ["harden", "--scan", "--verbose"])

        self.assertEqual(result.exit_code, 0)
        mock_invoke.assert_called_once_with(
            "harden",
            args=["--scan", "--verbose", "--config", "agentos_baseline"],
        )

    @patch("agent_sec_cli.cli.invoke")
    def test_harden_downstream_help_uses_backend_help(self, mock_invoke):
        mock_invoke.return_value = ActionResult(
            success=True,
            exit_code=0,
            stdout="seharden help\n",
        )

        result = self.runner.invoke(app, ["harden", "--downstream-help"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, "seharden help\n")
        mock_invoke.assert_called_once_with("harden", args=["--help"])


if __name__ == "__main__":
    unittest.main()
