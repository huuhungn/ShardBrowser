"""Phone profiles report the Chrome for Android build, under the Chrome brand; Apple M-series
profiles gain the WebGPU features Chrome 156 and 157 report there.

Run: python -m unittest discover -s sdks/python/tests (or pytest)."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path

# runtime.py on its own: no browser driver needed.
if "httpx" not in sys.modules:
    try:
        import httpx  # noqa: F401
    except ImportError:
        sys.modules["httpx"] = types.ModuleType("httpx")
RUNTIME_PY = Path(__file__).resolve().parents[1] / "shardx" / "runtime.py"
_spec = importlib.util.spec_from_file_location("shardx_runtime_phone_test", RUNTIME_PY)
rt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rt
_spec.loader.exec_module(rt)

M1 = "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"


def phone():
    return {"navigator": {"user_agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
                                        "(KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36"},
            "client_hints": {"mobile": True, "brand_full_version": "156.0.8078.48"}}


def mac(renderer, vendor, features):
    return {"webgl": {"renderer": renderer}, "webgpu": {"vendor": vendor, "features": features}}


class AndroidVersionTest(unittest.TestCase):
    def test_a_phone_gets_the_android_build(self):
        cfg = phone()
        rt.apply_engine_version(cfg, "157.0.8103.39", android_version="157.0.8103.38")
        ch = cfg["client_hints"]
        self.assertEqual((ch["brand_version"], ch["brand_full_version"], ch["chrome_patch"]),
                         ("157", "157.0.8103.38", 38))
        self.assertIn("Chrome/157.0.0.0 Mobile", cfg["navigator"]["user_agent"])

    def test_no_android_build_or_another_major_keeps_the_engines(self):
        for android in (None, "156.0.8078.81", "157.0.8103", ""):
            cfg = phone()
            rt.apply_engine_version(cfg, "157.0.8103.39", android_version=android)
            self.assertEqual(cfg["client_hints"]["brand_full_version"], "157.0.8103.39", android)


class ChromeBrandTest(unittest.TestCase):
    def test_a_missing_brand_becomes_google_chrome_and_a_named_one_stays(self):
        bare = phone()
        rt.apply_chrome_brand(bare)
        self.assertEqual(bare["client_hints"]["brand"], "Google Chrome")
        named = {"client_hints": {"brand": "Chromium"}}
        rt.apply_chrome_brand(named)
        self.assertEqual(named["client_hints"]["brand"], "Chromium")
        no_hints = {}
        rt.apply_chrome_brand(no_hints)
        self.assertEqual(no_hints, {})


class AppleWebGpuTest(unittest.TestCase):
    def test_an_apple_m_list_gains_the_feature_in_sorted_place_once(self):
        cfg = mac(M1, "apple", ["shader-f16", "texture-compression-etc2", "texture-formats-tier1"])
        rt.apply_apple_webgpu_features(cfg)
        rt.apply_apple_webgpu_features(cfg)
        self.assertEqual(cfg["webgpu"]["features"], [
            "shader-f16", "texture-compression-etc2", "texture-compression-unaligned", "texture-formats-tier1"])

    def test_m2_and_later_also_gain_the_chrome_157_feature_m1_does_not(self):
        m3 = mac("ANGLE (Apple, ANGLE Metal Renderer: Apple M3 Max, Unspecified Version)", "apple",
                 ["shader-f16", "texture-compression-unaligned"])
        rt.apply_apple_webgpu_features(m3)
        self.assertEqual(m3["webgpu"]["features"],
                         ["atomic-vec2u-min-max", "shader-f16", "texture-compression-unaligned"])
        m1 = mac(M1, "apple", ["shader-f16", "texture-compression-unaligned"])
        rt.apply_apple_webgpu_features(m1)
        self.assertEqual(m1["webgpu"]["features"], ["shader-f16", "texture-compression-unaligned"])

    def test_other_gpus_and_an_empty_list_are_left_alone(self):
        for cfg in (mac("ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics)", "intel", ["shader-f16"]),
                    mac(M1, "intel", ["shader-f16"]),
                    mac(M1, "apple", [])):
            before = repr(cfg)
            rt.apply_apple_webgpu_features(cfg)
            self.assertEqual(repr(cfg), before)


if __name__ == "__main__":
    unittest.main()
