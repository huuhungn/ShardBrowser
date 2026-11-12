"""`shardx install` / `python -m shardx install`: arguments reach the runtime, no network.

Run: python -m unittest discover -s sdks/python/tests (or pytest)."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path

# cli.py on its own, with a stand-in Runtime that records how it was called.
PKG = Path(__file__).resolve().parents[1] / "shardx"
pkg = types.ModuleType("shardx_cli_test")
pkg.__path__ = [str(PKG)]
sys.modules["shardx_cli_test"] = pkg


class FakeRuntime:
    calls = []
    chromium_version = "157.0.0.0"
    binary_path = Path("/engine/chrome")

    def __init__(self, cache_dir=None, progress=None):
        self.cache_dir, self.progress = cache_dir, progress

    def install(self, force=False):
        FakeRuntime.calls.append((self.cache_dir, force))


runtime_stub = types.ModuleType("shardx_cli_test.runtime")
runtime_stub.Runtime = FakeRuntime
sys.modules["shardx_cli_test.runtime"] = runtime_stub
_spec = importlib.util.spec_from_file_location("shardx_cli_test.cli", PKG / "cli.py")
cli = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cli
_spec.loader.exec_module(cli)


class InstallCliTest(unittest.TestCase):
    def setUp(self):
        FakeRuntime.calls.clear()

    def test_install_defaults(self):
        self.assertEqual(cli.main(["install"]), 0)
        self.assertEqual(FakeRuntime.calls, [(None, False)])

    def test_force_and_cache_dir_are_passed_on(self):
        self.assertEqual(cli.main(["install", "--force", "--cache-dir", "/opt/shardx"]), 0)
        self.assertEqual(FakeRuntime.calls, [("/opt/shardx", True)])

    def test_no_command_or_an_unknown_flag_exits_2_without_installing(self):
        for argv in ([], ["install", "--nope"]):
            with self.assertRaises(SystemExit) as e:
                cli.main(argv)
            self.assertEqual(e.exception.code, 2)
        self.assertEqual(FakeRuntime.calls, [])

    def test_progress_prints_every_tenth_percent(self):
        show = cli._progress_printer()
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for received in (0, 5, 10, 14, 19, 20, 100):
                show("Engine", received, 100)
            show("Engine", 1, 0)
        self.assertEqual(err.getvalue().splitlines(), ["Engine: 0%", "Engine: 10%", "Engine: 20%", "Engine: 100%"])


if __name__ == "__main__":
    unittest.main()
