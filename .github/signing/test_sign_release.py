"""Offline release-signing regression tests; never uses SSL.com credentials."""

from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

import sign_release as signing

VERIFY_JAR = signing.verify_jar


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


def manifest_bytes(main, entries=()):
    """Write physical UTF-8 byte continuations just as the JAR tools do."""
    lines = []
    for attributes in [main, *[[('Name', name), *attrs] for name, attrs in entries]]:
        for key, value in attributes:
            line = f"{key}: {value}".encode("utf-8")
            while len(line) > 72:
                lines.append(line[:72])
                line = b" " + line[72:]
            lines.append(line)
        lines.append(b"")
    return b"\r\n".join(lines) + b"\r\n"


class ManifestTests(unittest.TestCase):
    payload = {"payload.txt": b"original", "other.txt": b"other"}
    main = [("Manifest-Version", "1.0"), ("Created-By", "original tool"),
            ("Main-Class", "example.Main"), ("Class-Path", "lib/a.jar lib/b.jar"),
            ("Multi-Release", "true"), ("Sealed", "true"),
            ("Automatic-Module-Name", "example.plugin"), ("SHA-256-Digest", "application metadata")]

    def parsed(self, main=None, entries=()):
        return signing.parse_manifest(manifest_bytes(self.main if main is None else main, entries))

    def test_formatting_normalizes_case_order_newlines_and_utf8_byte_wrapping(self):
        first = (b"Manifest-Version: 1.0\r\nX-Info: \xc3\r\n \xa9\r\n\r\n"
                 b"Name: payload.txt\r\nSealed: false\r\nContent-Type: text/plain\r\n\r\n"
                 b"Name: other.txt\r\nX-Custom: preserved\r\n\r\n")
        second = ("x-info: é\nmanifest-version: 1.0\n\n"
                  "name: other.txt\nx-custom: preserved\n\n"
                  "NAME: payload.txt\ncontent-type: text/plain\nSEALED: false\n\n").encode()
        for newline in (b"\n", b"\r\n", b"\r"):
            with self.subTest(newline=newline):
                self.assertEqual(signing.parse_manifest(first), signing.parse_manifest(second.replace(b"\n", newline)))
        # Values can exceed one physical line and the spec requires support up to 65535 bytes.
        value = "é" * 32767 + "x"
        self.assertEqual(self.parsed([("Manifest-Version", "1.0"), ("X-Long", value)])[0]["x-long"], value)

    def test_every_existing_main_attribute_is_preserved(self):
        before = self.parsed()
        for key, value in self.main:
            for operation in ("change", "remove"):
                with self.subTest(key=key, operation=operation):
                    changed = [(k, "2.0" if k == key else v) for k, v in self.main] if operation == "change" else [
                        (k, v) for k, v in self.main if k != key]
                    with self.assertRaises(ValueError):
                        signing.check_manifest_parity(before, self.parsed(changed), self.payload)
        for key in ("Launcher-Agent-Class", "X-Added", "SHA-512-Digest"):
            with self.subTest(add=key), self.assertRaises(ValueError):
                signing.check_manifest_parity(before, self.parsed(self.main + [(key, "added")]), self.payload)
        with self.assertRaises(ValueError):
            signing.check_manifest_parity(before, None, self.payload)

    def test_entry_metadata_and_empty_sections_are_preserved(self):
        attrs = [("Sealed", "false"), ("Content-Type", "text/plain"), ("Magic", "custom"),
                 ("Application-Digest", "custom"), ("SHA-256-Digest-French", "custom")]
        for name in ("payload.txt", "example/", "https://example.invalid/external"):
            before = self.parsed(entries=[(name, attrs)])
            for key, value in attrs:
                for operation in ("change", "remove"):
                    with self.subTest(name=name, key=key, operation=operation):
                        changed = [(k, "changed" if k == key else v) for k, v in attrs] if operation == "change" else [
                            (k, v) for k, v in attrs if k != key]
                        with self.assertRaises(ValueError):
                            signing.check_manifest_parity(before, self.parsed(entries=[(name, changed)]), self.payload)
            with self.assertRaises(ValueError):
                signing.check_manifest_parity(before, self.parsed(), self.payload)
        with self.assertRaises(ValueError):
            signing.check_manifest_parity(self.parsed(entries=[("example/", [])]), self.parsed(), self.payload)

    def test_only_allowlisted_per_payload_digest_changes_are_allowed(self):
        for digest in signing.SIGNING_DIGESTS:
            with self.subTest(digest=digest):
                before = self.parsed(entries=[("payload.txt", [(digest, "old"), ("Sealed", "false")])])
                for attrs in ([(digest, "new"), ("Sealed", "false")], [("Sealed", "false")]):
                    signing.check_manifest_parity(before, self.parsed(entries=[("payload.txt", attrs)]), self.payload)
                signing.check_manifest_parity(self.parsed(), self.parsed(entries=[("payload.txt", [(digest, "new")])]), self.payload)
                for name in ("example/", "missing.txt", "https://example.invalid/external"):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        signing.check_manifest_parity(self.parsed(entries=[(name, [(digest, "old")])]),
                                                      self.parsed(entries=[(name, [(digest, "new")])]), self.payload)
        for name, attrs in (("payload.txt", []), ("missing.txt", [("SHA-256-Digest", "new")]),
                            ("example/", [("SHA-256-Digest", "new")]),
                            ("payload.txt", [("Magic", "new")]),
                            ("payload.txt", [("Application-Digest", "new")]),
                            ("payload.txt", [("SHA-256-Digest-French", "new")])):
            with self.subTest(name=name, attrs=attrs), self.assertRaises(ValueError):
                signing.check_manifest_parity(self.parsed(), self.parsed(entries=[(name, attrs)]), self.payload)

    def test_absent_manifest_allows_only_jdk_generated_main_defaults(self):
        for main in ([('Manifest-Version', '1.0')], [('Manifest-Version', '1.0'), ('Created-By', '21 (test JDK)')]):
            signing.check_manifest_parity(None, self.parsed(main, [('payload.txt', [('SHA-256-Digest', 'new')])]), self.payload)
        for key in ("Main-Class", "Class-Path", "Multi-Release", "Sealed", "SHA-256-Digest", "X-Added"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                signing.check_manifest_parity(None, self.parsed([('Manifest-Version', '1.0'), (key, 'added')]), self.payload)
        with self.assertRaises(ValueError):
            signing.check_manifest_parity(None, self.parsed([('Manifest-Version', '2.0')]), self.payload)
        with self.assertRaises(ValueError):
            signing.check_manifest_parity(self.parsed([('Manifest-Version', '1.0')]),
                                          self.parsed([('Manifest-Version', '1.0'), ('Created-By', 'added')]), self.payload)

    def test_malformed_and_ambiguous_manifests_are_rejected(self):
        prefix = b"Manifest-Version: 1.0\r\n"
        invalid = [b"", b"\n", b"\n" + prefix + b"\n", prefix.rstrip(), prefix,
                   prefix + b"X-Long: " + b"a" * 73 + b"\r\n\r\n",
                   prefix + b"X-Utf8: \xff\r\n\r\n", prefix + b"X-Nul: a\0b\r\n\r\n",
                   b" orphan\r\n\r\n", prefix + b"\r\n orphan\r\n\r\n",
                   prefix + b"X-No-Space:value\r\n\r\n", prefix + b"X!Bad: value\r\n\r\n",
                   prefix + b"A" * 71 + b": \r\n\r\n", prefix + b"Name: payload.txt\r\n\r\n",
                   b"X-No-Version: 1.0\r\n\r\n", b"Manifest-Version: invalid\r\n\r\n",
                   prefix + b"manifest-version: 1.0\r\n\r\n",
                   prefix + b"\r\nSealed: true\r\nName: payload.txt\r\n\r\n",
                   prefix + b"\r\nName: \r\n\r\n",
                   prefix + b"\r\nName: META-INF/MANIFEST.MF\r\n\r\n",
                   prefix + b"\r\nName: payload.txt\r\nname: other.txt\r\n\r\n",
                   prefix + b"\r\nName: payload.txt\r\nSHA-256-Digest: a\r\nsha-256-digest: b\r\n\r\n"]
        invalid.append(prefix + b"\r\nName: payload.txt\r\n\r\nName: payload.txt\r\n\r\n")
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                signing.parse_manifest(data)

    def test_entry_names_remain_case_sensitive(self):
        before = self.parsed(entries=[("Foo.class", [("Sealed", "true")]), ("foo.class", [("Sealed", "false")])])
        after = self.parsed(entries=[("foo.class", [("Sealed", "false")]), ("Foo.class", [("Sealed", "true")])])
        signing.check_manifest_parity(before, after, {"Foo.class": b"upper", "foo.class": b"lower"})
        with self.assertRaises(ValueError):
            signing.check_manifest_parity(before, self.parsed(entries=[("FOO.class", [("Sealed", "true")])]), self.payload)

    def test_noncanonical_manifest_paths_are_rejected(self):
        manifest = manifest_bytes(self.main)
        for names in (["meta-inf/manifest.mf"], ["META-INF/MANIFEST.MF/"],
                      ["META-INF/MANIFEST.MF", "META-INF/manifest.mf"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                signing.jar_manifest(zip_bytes({**self.payload, **dict.fromkeys(names, manifest)}))

    def test_signature_metadata_matches_jdk_reserved_names(self):
        reserved = ["META-INF/MANIFEST.MF", "META-INF/a.SF", "META-INF/a.rsa", "META-INF/a.DSA",
                    "META-INF/a.EC", "META-INF/SIG-TEST", "META-INF/SIG-a.x1", "meta-inf/sig-a.123"]
        ordinary = ["META-INF/SIG-CONFIG.properties", "META-INF/SIG-a.", "META-INF/SIG-a.ab-c",
                    "META-INF/SIG-a.é", "META-INF/services/a.SF", "other/MANIFEST.MF", "SIG-a"]
        for name in reserved:
            with self.subTest(name=name):
                self.assertTrue(signing.signature_metadata(name))
        for name in ordinary:
            with self.subTest(name=name):
                self.assertFalse(signing.signature_metadata(name))
        self.assertEqual(signing.jar_payload(zip_bytes(dict.fromkeys(reserved + ordinary, b"value"))),
                         dict.fromkeys(ordinary, b"value"))


def command(*args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    return result.stdout


@contextmanager
def timestamp_server(root):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = self.rfile.read(int(self.headers["Content-Length"]))
            (root / "request.tsq").write_bytes(request)
            result = subprocess.run(
                ["openssl", "ts", "-reply", "-config", "tsa.cnf", "-queryfile", "request.tsq"],
                cwd=root, capture_output=True, timeout=30)
            self.send_response(200 if result.returncode == 0 else 500)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(result.stdout)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class SigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="sslcom-tests-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = root = Path(cls.temp.name)
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=Signing Test Root", "-days", "2", "-keyout", "root.key",
                "-out", "root.crt", "-addext", "basicConstraints=critical,CA:TRUE", cwd=root)
        for index, (name, eku) in enumerate((("signer", "codeSigning"), ("tsa", "critical,timeStamping")), 2):
            command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN=Test {name}", "-keyout", f"{name}.key", "-out", f"{name}.csr", cwd=root)
            (root / f"{name}.ext").write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={eku}\n")
            command("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "root.crt",
                    "-CAkey", "root.key", "-set_serial", str(index), "-days", "2",
                    "-extfile", f"{name}.ext", "-out", f"{name}.crt", cwd=root)
        command("openssl", "pkcs12", "-export", "-in", "signer.crt", "-inkey", "signer.key",
                "-certfile", "root.crt", "-name", "signer", "-out", "signer.p12",
                "-passout", "pass:changeit", cwd=root)
        command("keytool", "-importcert", "-noprompt", "-alias", "root", "-file", "root.crt",
                "-keystore", "trust.p12", "-storepass", "changeit", cwd=root)
        der = command("openssl", "x509", "-in", "signer.crt", "-outform", "DER", cwd=root)
        cls.fingerprint = hashlib.sha256(der).hexdigest()
        (root / "tsa.serial").write_text("01\n")
        (root / "tsa.cnf").write_text("""[tsa]
default_tsa = tsa_config
[tsa_config]
serial = tsa.serial
crypto_device = builtin
signer_cert = tsa.crt
certs = root.crt
signer_key = tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256,sha384,sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
""")
        cls.unsigned = zip_bytes({"payload.txt": b"original payload", "META-INF/services/test": b"provider"})
        (root / "unsigned.jar").write_bytes(cls.unsigned)
        with timestamp_server(root) as tsa:
            command("jarsigner", "-keystore", "signer.p12", "-storepass", "changeit",
                    "-tsa", tsa, "-signedjar", "signed.jar", "unsigned.jar", "signer", cwd=root)
        cls.signed = (root / "signed.jar").read_bytes()
        command("jarsigner", "-keystore", "signer.p12", "-storepass", "changeit",
                "-signedjar", "no-timestamp.jar", "unsigned.jar", "signer", cwd=root)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="sslcom-case-")
        self.addCleanup(self.work.cleanup)
        self.bundle = Path(self.work.name) / "plugin.zip"
        self.bundle.write_bytes(zip_bytes({
            "plugin/plugin.xml": b"<plugin/>", "plugin/one.jar": self.unsigned,
            "plugin/two.jar": self.unsigned, "plugin/vendor.jar": b"vendor bytes",
            "plugin/webadmin.war": b"published WAR bytes", "plugin/web/plugin.js": b"web bytes",
        }))
        self.patterns = ["plugin/one.jar", "plugin/two.jar"]
        self.original = self.bundle.read_bytes()

    def verify(self, path, fingerprint=None):
        VERIFY_JAR(path, fingerprint or self.fingerprint, truststore=self.root / "trust.p12")

    def local_sign(self, source, output, tsa):
        command("jarsigner", "-keystore", str(self.root / "signer.p12"), "-storepass", "changeit",
                "-tsa", tsa, "-signedjar", str(output), str(source), "signer", cwd=self.root)

    def test_real_signed_timestamped_jar(self):
        self.verify(self.root / "signed.jar")

    def test_unsigned_jar_rejected(self):
        with self.assertRaisesRegex(ValueError, "verification failed"):
            self.verify(self.root / "unsigned.jar")

    def test_missing_timestamp_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing trusted timestamp"):
            self.verify(self.root / "no-timestamp.jar")

    def test_wrong_certificate_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unexpected signing certificate"):
            self.verify(self.root / "signed.jar", "0" * 64)

    def test_untrusted_certificate_rejected(self):
        with self.assertRaisesRegex(ValueError, "trust/signature verification failed"):
            signing.verify_jar(self.root / "signed.jar", self.fingerprint)

    def test_tampered_payload_rejected(self):
        path = Path(self.work.name) / "tampered.jar"
        with zipfile.ZipFile(io.BytesIO(self.signed)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries["payload.txt"] = b"tampered"
        path.write_bytes(zip_bytes(entries))
        with self.assertRaisesRegex(ValueError, "verification failed"):
            self.verify(path)

    def test_unsigned_added_resource_rejected(self):
        path = Path(self.work.name) / "partial.jar"
        path.write_bytes(self.signed)
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("META-INF/services/unsigned-provider", b"unsigned")
        with self.assertRaisesRegex(ValueError, "verification failed"):
            self.verify(path)

    def test_java_verifier_checks_ordinary_sig_prefixed_resources(self):
        for name in ("META-INF/SIG-CONFIG.properties", "META-INF/SIG-a.", "META-INF/SIG-a.ab-c"):
            with self.subTest(name=name):
                path = Path(self.work.name) / "partial.jar"
                path.write_bytes(self.signed)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr(name, b"unsigned")
                result = subprocess.run(["java", str(signing.HERE / "VerifyJar.java"), str(path), self.fingerprint],
                                        capture_output=True, text=True, timeout=60)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Expected one signer for " + name, result.stderr)

    def test_bad_input_manifest_fails_before_tool_download_or_paid_signing(self):
        manifests = [
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nclass-path: a\r\nClass-Path: b\r\n\r\n"},
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\nName: payload.txt\r\n\r\nName: payload.txt\r\n\r\n"},
            {"META-INF/manifest.mf": b"Manifest-Version: 1.0\r\n\r\n"},
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nX-Invalid: \xff\r\n\r\n"},
        ]
        for manifest in manifests:
            with self.subTest(manifest=manifest):
                original = zip_bytes({"plugin/one.jar": zip_bytes({"payload.txt": b"original", **manifest})})
                self.bundle.write_bytes(original)
                with patch.object(signing, "install_tool") as install, patch.object(signing, "cloud_sign") as cloud:
                    with self.assertRaises(ValueError):
                        signing.sign_bundle(self.bundle, ["plugin/one.jar"], self.fingerprint)
                    install.assert_not_called()
                    cloud.assert_not_called()
                self.assertEqual(self.bundle.read_bytes(), original)

    def test_changed_manifest_fails_before_verification_or_repacking(self):
        before = {"payload.txt": b"original", "META-INF/MANIFEST.MF": manifest_bytes(
            ManifestTests.main, [("example/", [("Sealed", "false")])])}
        mutations = [
            {**before, "META-INF/MANIFEST.MF": manifest_bytes(ManifestTests.main + [("Launcher-Agent-Class", "injected.Agent")])},
            {**before, "META-INF/MANIFEST.MF": manifest_bytes(ManifestTests.main, [("example/", [("Sealed", "true")])])},
            {**before, "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nX-Invalid: \xff\r\n\r\n"},
            {**before, "meta-inf/manifest.mf": manifest_bytes(ManifestTests.main)},
            {"payload.txt": b"original"},
        ]
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                original = zip_bytes({"plugin/one.jar": zip_bytes(before)})
                self.bundle.write_bytes(original)
                def sign(_tool, _inputs, outputs):
                    (outputs / "one.jar").write_bytes(zip_bytes(mutated))
                with patch.object(signing, "install_tool", return_value=Path("unused")), \
                        patch.object(signing, "cloud_sign", side_effect=sign), \
                        patch.object(signing, "verify_jar") as verify, patch.object(signing, "replace_jars") as replace:
                    with self.assertRaises(ValueError):
                        signing.sign_bundle(self.bundle, ["plugin/one.jar"], self.fingerprint)
                    verify.assert_not_called()
                    replace.assert_not_called()
                self.assertEqual(self.bundle.read_bytes(), original)

    def test_real_signing_preserves_runtime_manifest_and_sig_prefixed_resource(self):
        original = zip_bytes({"payload.txt": b"original", "META-INF/SIG-CONFIG.properties": b"setting=original",
                              "META-INF/MANIFEST.MF": manifest_bytes(ManifestTests.main,
                                  [("example/", [("Sealed", "false")]), ("payload.txt", [("Content-Type", "text/plain")])])})
        self.bundle.write_bytes(zip_bytes({"plugin/one.jar": original, "plugin/plugin.xml": b"unchanged"}))
        with timestamp_server(self.root) as tsa:
            def sign(_tool, inputs, outputs):
                self.local_sign(inputs / "one.jar", outputs / "one.jar", tsa)
            with patch.object(signing, "install_tool", return_value=Path("unused")), \
                    patch.object(signing, "cloud_sign", side_effect=sign), \
                    patch.object(signing, "verify_jar", side_effect=self.verify):
                signing.sign_bundle(self.bundle, ["plugin/one.jar"], self.fingerprint)
        with zipfile.ZipFile(self.bundle) as archive:
            signed = archive.read("plugin/one.jar")
            self.assertEqual(archive.read("plugin/plugin.xml"), b"unchanged")
        self.assertEqual(signing.jar_payload(original), signing.jar_payload(signed))
        signing.check_manifest_parity(signing.jar_manifest(original), signing.jar_manifest(signed), signing.jar_payload(original))

    def test_valid_signature_cannot_hide_manifest_or_sig_resource_mutation(self):
        original = {"payload.txt": b"original", "META-INF/SIG-CONFIG.properties": b"setting=original",
                    "META-INF/MANIFEST.MF": manifest_bytes([("Manifest-Version", "1.0"), ("Class-Path", "original.jar")])}
        for mutation in ("manifest", "resource"):
            with self.subTest(mutation=mutation), timestamp_server(self.root) as tsa:
                before = zip_bytes({"plugin/one.jar": zip_bytes(original)})
                self.bundle.write_bytes(before)
                def sign(_tool, inputs, outputs):
                    changed = dict(original)
                    if mutation == "manifest":
                        changed["META-INF/MANIFEST.MF"] = manifest_bytes([("Manifest-Version", "1.0"), ("Class-Path", "injected.jar")])
                    else:
                        changed["META-INF/SIG-CONFIG.properties"] = b"setting=injected"
                    source = inputs / "changed.jar"
                    source.write_bytes(zip_bytes(changed))
                    self.local_sign(source, outputs / "one.jar", tsa)
                    self.verify(outputs / "one.jar")  # Cryptographically valid, wrong application semantics.
                with patch.object(signing, "install_tool", return_value=Path("unused")), \
                        patch.object(signing, "cloud_sign", side_effect=sign), \
                        patch.object(signing, "verify_jar") as verify:
                    with self.assertRaisesRegex(ValueError, "Signing changed the JAR"):
                        signing.sign_bundle(self.bundle, ["plugin/one.jar"], self.fingerprint)
                    verify.assert_not_called()
                self.assertEqual(self.bundle.read_bytes(), before)

    def test_signed_bundle_preserves_other_entries(self):
        def sign(_tool, inputs, outputs):
            for path in inputs.iterdir():
                (outputs / path.name).write_bytes(self.signed)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign), \
                patch.object(signing, "verify_jar", side_effect=self.verify):
            signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        with zipfile.ZipFile(io.BytesIO(self.original)) as before, zipfile.ZipFile(self.bundle) as after:
            self.assertEqual(before.namelist(), after.namelist())
            for name in before.namelist():
                self.assertEqual(after.read(name), self.signed if name in self.patterns else before.read(name))

    def test_partial_batch_leaves_original_bundle(self):
        def sign(_tool, _inputs, outputs):
            (outputs / "one.jar").write_bytes(self.signed)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign):
            with self.assertRaisesRegex(ValueError, "exactly the requested"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_success_exit_with_unsigned_files_leaves_original_bundle(self):
        def sign(_tool, inputs, outputs):
            for path in inputs.iterdir():
                shutil.copyfile(path, outputs / path.name)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign), \
                patch.object(signing, "verify_jar", side_effect=self.verify):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_second_jar_failure_does_not_commit_first(self):
        def sign(_tool, _inputs, outputs):
            (outputs / "one.jar").write_bytes(self.signed)
            (outputs / "two.jar").write_bytes(self.unsigned)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign), \
                patch.object(signing, "verify_jar", side_effect=self.verify):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_changed_payload_rejected_before_repacking(self):
        def sign(_tool, _inputs, outputs):
            (outputs / "one.jar").write_bytes(zip_bytes({"payload.txt": b"changed"}))
            (outputs / "two.jar").write_bytes(self.signed)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign):
            with self.assertRaisesRegex(ValueError, "changed the JAR payload"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_extra_output_rejected_before_repacking(self):
        def sign(_tool, _inputs, outputs):
            for name in ["one.jar", "two.jar", "unexpected.jar"]:
                (outputs / name).write_bytes(self.signed)
        with patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=sign):
            with self.assertRaisesRegex(ValueError, "exactly the requested"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_cloud_failure_preserves_bundle_and_cleans_working_directory(self):
        root = Path(self.work.name) / "runner-temp"
        root.mkdir()
        with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                patch.object(signing, "install_tool", return_value=Path("unused")), \
                patch.object(signing, "cloud_sign", side_effect=ValueError("service unavailable")):
            with self.assertRaisesRegex(ValueError, "service unavailable"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(self.bundle.read_bytes(), self.original)

    def test_repack_failure_is_atomic(self):
        with patch.object(signing.os, "replace", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(OSError, "disk failure"):
                signing.replace_jars(self.bundle, {"plugin/one.jar": self.signed})
        self.assertEqual(self.bundle.read_bytes(), self.original)
        self.assertEqual(list(self.bundle.parent.glob("*.signed.zip")), [])

    def test_missing_and_ambiguous_jar_selection(self):
        for patterns in (["plugin/missing.jar"], ["plugin/*.jar"], [], ["plugin/one.jar"] * 2):
            with self.subTest(patterns=patterns), zipfile.ZipFile(self.bundle) as archive:
                with self.assertRaises(ValueError):
                    signing.select_jars(archive, patterns)

    def test_unsafe_and_duplicate_zip_entries_rejected(self):
        for names in (["../escape.jar"], ["/absolute.jar"], ["a.jar", "a.jar"]):
            with self.subTest(names=names):
                data = io.BytesIO()
                with zipfile.ZipFile(data, "w") as archive:
                    for name in names:
                        archive.writestr(name, self.unsigned)
                with zipfile.ZipFile(data) as archive, self.assertRaises(ValueError):
                    signing.select_jars(archive, ["*.jar"])

    def test_missing_secrets_and_invalid_fingerprint(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "Missing GitHub Actions secrets"):
                signing.check_config()
        env = {name: "fixture-only" for name in signing.SECRET_NAMES}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "SSL_COM_CERT_SHA256"):
                signing.check_config()
        env["SSL_COM_CERT_SHA256"] = ":".join(["AB"] * 32)
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(signing.check_config(), "ab" * 32)

    def test_tool_digest_mismatch_rejected(self):
        with patch.object(signing.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong binary")):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                signing.install_tool(Path(self.work.name) / "tool")

    def test_credentials_are_literal_arguments_and_not_error_output(self):
        env = {name: 'sensitive " $() ` value' for name in signing.SECRET_NAMES}
        env['CODESIGNTOOL_JAVA'] = '/private/java11/bin/java'
        inputs, outputs = Path(self.work.name) / "inputs", Path(self.work.name) / "outputs"
        inputs.mkdir()
        outputs.mkdir()
        (inputs / "one with spaces.jar").write_bytes(self.unsigned)
        with patch.dict(os.environ, env), patch.object(signing.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = b"a sensitive access token"
            with self.assertRaises(ValueError) as error:
                signing.cloud_sign(Path("/tmp/tool/jar/tool.jar"), inputs, outputs)
            self.assertNotIn("sensitive", str(error.exception))
            self.assertEqual(run.call_args.args[0][0], env["CODESIGNTOOL_JAVA"])
            self.assertIn("-password=" + env["SSL_COM_PASSWORD"], run.call_args.args[0])
            self.assertFalse(run.call_args.kwargs.get("shell", False))
            self.assertIn("sign", run.call_args.args[0])
            self.assertIn("-input_file_path=" + str(inputs / "one with spaces.jar"), run.call_args.args[0])

    def test_missing_tool_runtime_fails_before_cloud_request(self):
        for value in ("", "java", "relative/java"):
            with self.subTest(value=value), patch.dict(os.environ, {"CODESIGNTOOL_JAVA": value}), \
                    patch.object(signing.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "JDK 11"):
                    signing.cloud_sign(Path("unused"), Path("in"), Path("out"))
                run.assert_not_called()

    def test_zero_exit_with_service_error_is_rejected_without_leaking_output(self):
        inputs, outputs = Path(self.work.name) / "inputs", Path(self.work.name) / "outputs"
        inputs.mkdir()
        outputs.mkdir()
        (inputs / "one.jar").write_bytes(self.unsigned)
        env = {name: "fixture-only" for name in signing.SECRET_NAMES}
        env["CODESIGNTOOL_JAVA"] = "/private/java11/bin/java"
        with patch.dict(os.environ, env), patch.object(signing.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b"access_token=private-response-token\nError: invalid otp"
            with self.assertRaisesRegex(ValueError, "invalid signing OTP") as error:
                signing.cloud_sign(Path("/tmp/tool/jar/tool.jar"), inputs, outputs)
            self.assertNotIn("private-response-token", str(error.exception))
            self.assertNotIn("access_token", str(error.exception))
            self.assertEqual(run.call_count, 1)

    def test_unrecognized_zero_exit_failure_does_not_leak_vendor_output(self):
        inputs, outputs = Path(self.work.name) / "inputs", Path(self.work.name) / "outputs"
        inputs.mkdir()
        outputs.mkdir()
        (inputs / "one.jar").write_bytes(self.unsigned)
        env = {name: "fixture-only" for name in signing.SECRET_NAMES}
        env["CODESIGNTOOL_JAVA"] = "/private/java11/bin/java"
        with patch.dict(os.environ, env), patch.object(signing.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b"private-unrecognized-vendor-response"
            with self.assertRaisesRegex(ValueError, "SSL.com signing failed") as error:
                signing.cloud_sign(Path("/tmp/tool/jar/tool.jar"), inputs, outputs)
            self.assertNotIn("private-unrecognized-vendor-response", str(error.exception))
            self.assertEqual(run.call_count, 1)

    def test_release_workflow_orders_signing_before_publication(self):
        workflow = (signing.HERE.parent / "workflows/release.yml").read_text()
        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", workflow)
        preflight = workflow.index("sign_release.py --check-config")
        self.assertIn("steps.codesign-java.outputs.path", workflow)
        self.assertIn("sign_release.py --check-tool", workflow)
        sign = workflow.index("run: python3 .github/signing/sign_release.py\n")
        build = workflow.index("run: mvn -B -ntp verify\n")
        post_sign = workflow.index("run: mvn -B -ntp failsafe:integration-test failsafe:verify\n")
        checksum = workflow.index("sha256sum", sign)
        publish = workflow.index("uses: softprops/action-gh-release@")
        self.assertLess(preflight, sign)
        self.assertLess(build, sign)
        self.assertLess(sign, post_sign)
        self.assertLess(post_sign, checksum)
        self.assertLess(checksum, publish)
        for command_line in re.findall(r"\bmvn\s+([^\n]+)", workflow[sign:publish]):
            self.assertFalse(set(command_line.split()) & {"clean", "compile", "test", "package", "verify", "install", "deploy"},
                             "A Maven lifecycle after signing would rebuild the unsigned artifact")
        config = json.loads((signing.HERE / "config.json").read_text())
        self.assertTrue(config["bundle"].endswith(".zip"))
        self.assertTrue(config["jars"])

    def test_multiple_jars_use_individual_sign_commands(self):
        inputs, outputs = Path(self.work.name) / "inputs", Path(self.work.name) / "outputs"
        inputs.mkdir()
        outputs.mkdir()
        for name in ("one.jar", "two.jar"):
            (inputs / name).write_bytes(self.unsigned)
        env = {name: "fixture-only" for name in signing.SECRET_NAMES}
        env["CODESIGNTOOL_JAVA"] = "/private/java11/bin/java"

        def sign(command, **kwargs):
            source = Path(next(value.split("=", 1)[1] for value in command if value.startswith("-input_file_path=")))
            self.assertEqual(command[3], "sign")
            self.assertFalse(any(value.startswith("-input_dir_path=") for value in command))
            (outputs / source.name).write_bytes(self.signed)
            return subprocess.CompletedProcess(command, 0, b"success")

        with patch.dict(os.environ, env), patch.object(signing.subprocess, "run", side_effect=sign) as run:
            signing.cloud_sign(Path("/tmp/tool/jar/tool.jar"), inputs, outputs)
            self.assertEqual(run.call_count, 2)
        for name in ("one.jar", "two.jar"):
            self.assertEqual((inputs / name).read_bytes(), self.unsigned)
            self.verify(outputs / name)

    def test_second_service_failure_preserves_zip_and_does_not_retry(self):
        env = {name: "fixture-only" for name in signing.SECRET_NAMES}
        env["CODESIGNTOOL_JAVA"] = "/private/java11/bin/java"
        calls = []
        scratch = []

        def sign(command, **kwargs):
            calls.append(command)
            outputs = Path(next(value.split("=", 1)[1] for value in command if value.startswith("-output_dir_path=")))
            scratch.append(outputs.parent)
            if len(calls) == 1:
                (outputs / "one.jar").write_bytes(self.signed)
            return subprocess.CompletedProcess(command, 0, b"private-vendor-response")

        with patch.dict(os.environ, env), \
                patch.object(signing, "install_tool", return_value=Path("/tmp/tool/jar/tool.jar")), \
                patch.object(signing.subprocess, "run", side_effect=sign):
            with self.assertRaisesRegex(ValueError, "SSL.com signing failed"):
                signing.sign_bundle(self.bundle, self.patterns, self.fingerprint)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.bundle.read_bytes(), self.original)
        self.assertTrue(all(not path.exists() for path in scratch))


if __name__ == "__main__":
    unittest.main()
