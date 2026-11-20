"""install() extracts only archives whose SHA-256 the manifest names.

Run: python -m unittest discover -s sdks/python/tests (or pytest)."""
import contextlib
import hashlib
import importlib.util
import io
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

# runtime.py on its own: no browser driver needed, and httpx is stood in for below.
if "httpx" not in sys.modules:
    try:
        import httpx  # noqa: F401
    except ImportError:
        sys.modules["httpx"] = types.ModuleType("httpx")
RUNTIME_PY = Path(__file__).resolve().parents[1] / "shardx" / "runtime.py"
_spec = importlib.util.spec_from_file_location("shardx_runtime_sha256_test", RUNTIME_PY)
rt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rt
_spec.loader.exec_module(rt)


def zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("marker.txt", "engine")
    return buf.getvalue()


class _Response:
    def __init__(self, body=b"", manifest=None):
        self.status_code = 200
        self.headers = {"etag": '"etag"', "content-length": str(len(body))}
        self._body, self._manifest = body, manifest

    def json(self):
        return self._manifest

    def raise_for_status(self):
        pass

    def iter_bytes(self, chunk_size=1 << 16):
        yield self._body


class FakeHttpx:
    """The manifest names `hash` (or nothing) for every archive; the bucket serves `body`."""

    def __init__(self, body, keys, hash_):
        self.body = body
        self.manifest = {"archives": {k: "etag" for k in keys}}
        if hash_:
            self.manifest["sha256"] = {k: hash_ for k in keys}

    def Client(self, **_):
        return contextlib.nullcontext(self)

    def get(self, url):
        assert url == rt.MANIFEST_URL, url
        return _Response(manifest=self.manifest)

    @contextlib.contextmanager
    def stream(self, method, url, **_):
        yield _Response(body=self.body)


class InstallChecksSha256(unittest.TestCase):
    def install(self, hash_):
        body = zip_bytes()
        spec = rt.host_spec()
        keys = [a.key for a in (spec.browser, spec.widevine, rt.FINGERPRINTS_ARCHIVE) if a]
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        # A forced reinstall over an engine already on disk.
        old_engine = root / spec.binary_subpath[0] / "old-engine"
        old_engine.parent.mkdir(parents=True)
        old_engine.write_text("working engine")
        real = rt.httpx
        rt.httpx = FakeHttpx(body, keys, hash_)
        try:
            rt.Runtime(cache_dir=root).install(force=True)
            error = None
        except RuntimeError as e:
            error = str(e)
        finally:
            rt.httpx = real
        return error, (root / "marker.txt").exists(), old_engine.exists()

    def test_an_archive_with_no_checksum_is_not_extracted(self):
        error, extracted, kept = self.install(None)
        self.assertIn("no SHA-256", error or "")
        self.assertFalse(extracted)
        self.assertTrue(kept, "a refused archive must not cost the engine already installed")

    def test_an_archive_that_does_not_match_is_not_extracted(self):
        error, extracted, kept = self.install("0" * 64)
        self.assertIn("does not match the SHA-256", error or "")
        self.assertFalse(extracted)
        self.assertTrue(kept)

    def test_the_named_archive_is_extracted(self):
        error, extracted, kept = self.install(hashlib.sha256(zip_bytes()).hexdigest().upper())
        self.assertIsNone(error)
        self.assertTrue(extracted)
        self.assertFalse(kept, "a verified engine replaces the old tree")


if __name__ == "__main__":
    unittest.main()
