"""A phone keeps the handset's screen whatever the screen mode says.

Run: python -m unittest discover -s sdks/python/tests (or pytest)."""
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

# The package on its own: no browser driver needed.
if "httpx" not in sys.modules:
    try:
        import httpx  # noqa: F401
    except ImportError:
        sys.modules["httpx"] = types.ModuleType("httpx")
PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
try:
    import shardx  # noqa: F401
except ImportError:
    # The package __init__ pulls in the browser driver; the modules under test do not need it.
    stub = types.ModuleType("shardx")
    stub.__path__ = [str(PKG / "shardx")]
    sys.modules["shardx"] = stub

from shardx import screen  # noqa: E402
from shardx.profile import config_claims_mobile  # noqa: E402


def phone():
    return {"client_hints": {"mobile": True},
            "screen": {"width": 412, "height": 915, "avail_width": 412, "avail_height": 915},
            "window": {"outer_width": 412, "outer_height": 915, "inner_width": 412, "inner_height": 800}}


class PhoneScreenTest(unittest.TestCase):
    def test_a_phone_is_recognised_by_the_engines_three_signals(self):
        self.assertTrue(config_claims_mobile({"client_hints": {"mobile": True}}))
        self.assertTrue(config_claims_mobile({"client_hints": {"platform": "Android"}}))
        self.assertTrue(config_claims_mobile({"navigator": {"user_agent": "Mozilla/5.0 (Linux; Android 10; K)"}}))
        self.assertFalse(config_claims_mobile({"navigator": {"platform": "Linux armv8l"}}))

    def test_every_screen_mode_leaves_a_phones_screen_and_a_desktops_follows_the_host(self):
        with mock.patch.object(screen, "host_screen_size", return_value=(1366, 768)):
            for mode in ("profile", "cap_to_host", "use_host"):
                cfg = phone()
                screen.apply_screen_strategy(cfg, mode)
                self.assertEqual(cfg, phone(), mode)
            desktop = {"screen": {"width": 2560, "height": 1440, "avail_width": 2560, "avail_height": 1400},
                       "window": {"outer_width": 2560, "outer_height": 1400, "inner_width": 2560, "inner_height": 1300}}
            screen.apply_screen_strategy(desktop, "use_host")
            self.assertEqual(desktop["screen"]["width"], 1366)


if __name__ == "__main__":
    unittest.main()
