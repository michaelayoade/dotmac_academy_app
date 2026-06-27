import json
import os
import subprocess

from .interface import ExecResult, LabEngine, LabHandle

# containerlab needs root (netns/bridges); the app/worker run unprivileged, so
# invoke it via passwordless sudo. docker exec / ssh stay unprivileged.
_CLAB = ("sudo", "-n", "containerlab")


class ContainerlabEngine(LabEngine):
    def __init__(self, workdir: str):
        self.workdir = workdir

    def _topo_path(self, instance_name: str) -> str:
        d = os.path.join(self.workdir, instance_name)
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "topo.clab.yml")

    def deploy(self, topology_text: str, instance_name: str) -> LabHandle:
        path = self._topo_path(instance_name)
        with open(path, "w") as f:
            f.write(topology_text)
        r = subprocess.run(
            [*_CLAB, "deploy", "-t", path, "--format", "json"],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"deploy failed: {r.stderr}")
        nodes, mgmt, kinds = {}, {}, {}
        prefix = f"clab-{instance_name}-"  # containerlab names: clab-<labname>-<node>
        data = json.loads(r.stdout)
        # `containerlab deploy --format json` → {"<labname>": [ {node...} ]}.
        # Be tolerant of a bare list too (older format / unit-test fixtures).
        if isinstance(data, dict):
            items = data.get(instance_name) or next(iter(data.values()), [])
        else:
            items = data
        for item in items:
            cname = item["name"]
            # strip the known prefix so dashed node names (e.g. client-a) survive
            logical = cname[len(prefix):] if cname.startswith(prefix) else cname.split("-")[-1]
            nodes[logical] = cname
            mgmt[logical] = (item.get("ipv4_address") or "").split("/")[0]
            kinds[logical] = item.get("kind", "linux")
        return LabHandle(instance_name=instance_name, nodes=nodes, mgmt=mgmt, kinds=kinds)

    def ssh_exec(
        self,
        handle: LabHandle,
        node: str,
        command: str,
        user: str = "admin",
        password: str = "",
    ) -> ExecResult:
        ip = handle.mgmt[node]
        ssh = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{user}@{ip}",
            command,
        ]
        r = subprocess.run(ssh, capture_output=True, text=True)
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def destroy(self, instance_name: str) -> None:
        path = self._topo_path(instance_name)
        subprocess.run(
            [*_CLAB, "destroy", "-t", path, "--cleanup"],
            capture_output=True,
            text=True,
        )

    def reset(self, topology_text: str, instance_name: str) -> LabHandle:
        self.destroy(instance_name)
        return self.deploy(topology_text, instance_name)

    def exec(self, handle: LabHandle, node: str, command: list) -> ExecResult:
        cname = handle.nodes[node]
        r = subprocess.run(
            ["docker", "exec", cname, *command],
            capture_output=True,
            text=True,
        )
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def status(self, instance_name: str) -> str:
        path = self._topo_path(instance_name)
        r = subprocess.run(
            [*_CLAB, "inspect", "-t", path, "--format", "json"],
            capture_output=True,
            text=True,
        )
        return "running" if r.returncode == 0 else "absent"

    def console_target(self, handle: LabHandle, node: str) -> str:
        return handle.nodes[node]
