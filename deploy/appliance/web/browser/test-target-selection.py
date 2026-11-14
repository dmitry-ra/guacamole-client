#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
"""Render current Guacamole login fields with the actual portal target resource."""
import argparse
import base64
import hashlib
import html
import http.server
import io
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile
import threading
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[4]
FRONTEND = ROOT / "guacamole/src/main/frontend"
FIXTURE = pathlib.Path(__file__).with_name("target-selection.html")
parser = argparse.ArgumentParser()
parser.add_argument("--artifacts", type=pathlib.Path)
args = parser.parse_args()
if args.artifacts:
    args.artifacts.mkdir(parents=True)
lock = json.loads((FRONTEND / "package-lock.json").read_text())
with tempfile.TemporaryDirectory(prefix="guacamole-portal-browser-") as temp:
    temporary = pathlib.Path(temp)
    vendor = temporary / "vendor"
    vendor.mkdir()
    for package, member, name in [
        ("jquery", "package/dist/jquery.js", "jquery.js"),
        ("angular", "package/angular.js", "angular.js"),
        ("angular-translate", "package/dist/angular-translate.js", "angular-translate.js"),
        ("lodash", "package/lodash.js", "lodash.js"),
    ]:
        spec = lock["packages"]["node_modules/" + package]
        with urllib.request.urlopen(spec["resolved"], timeout=30) as response:
            data = response.read(16000000)
        expected = spec["integrity"].split("sha512-")[1]
        assert base64.b64encode(hashlib.sha512(data).digest()).decode() == expected
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            (vendor / name).write_bytes(archive.extractfile(member).read())

    class Handler(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, path):
            path = path.split("?", 1)[0]
            if path == "/":
                return str(FIXTURE)
            if path.startswith("/portal/"):
                return str(FIXTURE.parent.parent / pathlib.Path(path).name)
            if path.startswith("/vendor/"):
                return str(vendor / pathlib.Path(path).name)
            return str(FRONTEND / "src" / path.lstrip("/"))

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    failures = 0
    try:
        for width in (1280,):
            for mode in ("", "?continuation"):
                name = str(width) + "-" + (mode.lstrip("?") or "initial")
                profile = temporary / name
                command = ["/usr/bin/google-chrome", "--headless", "--disable-gpu",
                           "--no-first-run", "--no-default-browser-check",
                           "--user-data-dir=" + str(profile),
                           "--window-size=" + str(width) + ",800",
                           "--force-device-scale-factor=1", "--hide-scrollbars",
                           "--virtual-time-budget=5000", "--dump-dom",
                           "http://127.0.0.1:" + str(server.server_port) + "/" + mode + "#/?wrdp-target=desktop-b"]
                if args.artifacts:
                    command.insert(-1, "--screenshot=" + str(args.artifacts.resolve() / (name + ".png")))
                run = subprocess.run(command, capture_output=True, text=True, timeout=30)
                match = re.search(r'<pre id="result">(.*?)</pre>', run.stdout, re.S)
                if run.returncode or not match or not match.group(1):
                    raise RuntimeError("Chrome did not return browser results: " + run.stderr[-1500:])
                result = json.loads(html.unescape(match.group(1)))
                print(json.dumps(result, sort_keys=True), flush=True)
                if args.artifacts:
                    (args.artifacts / (name + ".json")).write_text(json.dumps(result, indent=2))
                    (args.artifacts / (name + ".stderr")).write_text(run.stderr)
                failures += bool(result.get("fatal") or result.get("errors"))
    finally:
        server.shutdown()
    raise SystemExit(bool(failures))
