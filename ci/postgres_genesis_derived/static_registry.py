"""Read-only static registry for one reviewed OCI layout; GET/HEAD only, nothing can be pushed or converted."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

ROOT = Path("/srv")
NAME = "academy-genesis"
DIGEST = re.compile(r"sha256:([0-9a-f]{64})", re.ASCII)
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")


class Refused(Exception):
    """No external text escapes."""


def need(condition):
    if not condition:
        raise Refused


def load(root):
    index = json.loads((root / "index.json").read_bytes())
    need(index["schemaVersion"] == 2 and len(index["manifests"]) == 1 and "annotations" not in index)
    descriptor = index["manifests"][0]
    need(descriptor["mediaType"] in MANIFEST_TYPES and DIGEST.fullmatch(descriptor["digest"]) is not None)
    manifest_path = root / "blobs/sha256" / descriptor["digest"].removeprefix("sha256:")
    data = manifest_path.read_bytes()
    need(len(data) == descriptor["size"] and "sha256:" + hashlib.sha256(data).hexdigest() == descriptor["digest"])
    manifest = json.loads(data)
    allowed = {manifest["config"]["digest"], *(layer["digest"] for layer in manifest["layers"])}
    need(all(DIGEST.fullmatch(value) is not None for value in allowed))
    return descriptor, data, allowed


class Handler(BaseHTTPRequestHandler):
    server_version = "academy-static-registry"
    protocol_version = "HTTP/1.1"
    descriptor: ClassVar[dict] = {}
    manifest = b""
    blobs: ClassVar[frozenset] = frozenset()

    def log_message(self, *_args):
        return

    def reply(self, status, headers=(), body=b"", head=False):
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head and body:
            self.wfile.write(body)

    def serve(self, head):
        path = self.path
        if "?" in path or "#" in path:
            return self.reply(404, head=head)
        if path in ("/v2/", "/v2"):
            return self.reply(200, [("Docker-Distribution-API-Version", "registry/2.0")], b"{}", head)
        match = re.fullmatch(r"/v2/" + NAME + r"/(manifests|blobs)/(sha256:[0-9a-f]{64})", path)
        if match is None:
            return self.reply(404, head=head)
        kind, value = match.groups()
        if kind == "manifests" and value == self.descriptor["digest"]:
            return self.reply(
                200,
                [("Content-Type", self.descriptor["mediaType"]), ("Docker-Content-Digest", value)],
                self.manifest,
                head,
            )
        if kind == "blobs" and value in self.blobs:
            file = ROOT / "blobs/sha256" / value.removeprefix("sha256:")
            descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                need(stat.S_ISREG(info.st_mode))
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Docker-Content-Digest", value)
                self.send_header("Content-Length", str(info.st_size))
                self.send_header("Connection", "close")
                self.end_headers()
                while not head and (chunk := stream.read(1048576)):
                    self.wfile.write(chunk)
            return None
        return self.reply(404, head=head)

    def do_GET(self):
        self.serve(False)

    def do_HEAD(self):
        self.serve(True)

    def method_refused(self):
        self.reply(405, [("Allow", "GET, HEAD")])

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = method_refused


def main():
    descriptor, manifest, blobs = load(ROOT)
    Handler.descriptor, Handler.manifest, Handler.blobs = descriptor, manifest, frozenset(blobs)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104 -- container port, published to loopback only


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
