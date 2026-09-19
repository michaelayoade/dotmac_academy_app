import json
import os
import subprocess

import yaml

from app.config import settings

from .interface import ExecResult, LabEngine, LabHandle, WrongLabHostError

# containerlab needs root (netns/bridges); the app/worker run unprivileged, so
# invoke it via passwordless sudo. docker exec / ssh stay unprivileged.
_CLAB = ("sudo", "-n", "containerlab")
_INSPECT_TIMEOUT_SECONDS = 60
_DEPLOY_TIMEOUT_SECONDS = 900
_DESTROY_TIMEOUT_SECONDS = 420
_CHECK_COMMAND_TIMEOUT_SECONDS = 480


def _requires_kvm(topology_text: str) -> bool:
    """Return whether parsed topology declares a vr-* node kind anywhere.

    Containerlab permits ``kind`` on a node, group, or ``defaults`` block.
    Walking the parsed document keeps this fail-closed as those inheritance
    forms evolve, without relying on YAML spelling or quoting.
    """
    topology = yaml.safe_load(topology_text) or {}

    def _walk(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                (key == "kind" and isinstance(child, str) and child.startswith("vr-"))
                or _walk(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(_walk(child) for child in value)
        return False

    return _walk(topology)


class ContainerlabEngine(LabEngine):
    def __init__(self, workdir: str, lab_host_role: str | None = None):
        self.workdir = workdir
        self.lab_host_role = lab_host_role if lab_host_role is not None else settings.lab_host_role

    def _require_lab_host(self) -> None:
        if self.lab_host_role.lower() != "lab":
            from app.metrics import LAB_WRONG_HOST_REFUSALS

            LAB_WRONG_HOST_REFUSALS.inc()
            raise WrongLabHostError(
                f"containerlab operations require LAB_HOST_ROLE=lab (got {self.lab_host_role!r})"
            )

    def _topo_path(self, instance_name: str) -> str:
        return os.path.join(self.workdir, instance_name, "topo.clab.yml")

    def _inspect_all(self) -> object:
        result = subprocess.run(
            [*_CLAB, "inspect", "--all", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise RuntimeError(f"inspect failed: {result.stderr}")
        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("inspect returned invalid JSON") from exc

    def _inspect_lab_paths(self) -> dict[str, str]:
        """Every containerlab-reported lab name -> its real topology path.

        Unfiltered by design: a caller that already knows (by row identity)
        which specific instance it means to act on — e.g. ``destroy()``
        below, recovering the real path for a lab whose expected topology
        file went missing — needs whatever path containerlab actually
        reports, not an ownership judgement about it. :meth:`inventory` is
        the ownership-filtered view built on top of this for callers (like
        ``reconcile_runtime``) that must decide *which* names are Academy's
        to manage in the first place.
        """
        self._require_lab_host()
        raw = self._inspect_all()
        found: dict[str, str] = {}

        def _walk(value: object, hinted_name: str | None = None) -> None:
            if isinstance(value, dict):
                lab_name = value.get("lab_name")
                if not isinstance(lab_name, str) or not lab_name:
                    lab_name = hinted_name
                path = value.get("absLabPath") or value.get("labPath")
                if isinstance(lab_name, str) and lab_name:
                    found.setdefault(lab_name, path if isinstance(path, str) else "")
                    if isinstance(path, str) and path:
                        found[lab_name] = path
                for key, child in value.items():
                    child_hint = key if isinstance(child, list) else lab_name
                    _walk(child, child_hint)
            elif isinstance(value, list):
                for child in value:
                    _walk(child, hinted_name)

        _walk(raw)
        return found

    def inventory(self) -> dict[str, str]:
        """Inspect every containerlab runtime, keeping only labs this engine owns.

        A ``dal-``-prefixed name alone is not proof of ownership — an unrelated
        containerlab lab on the same host (an operator's own test, or plain
        coincidence) could share that naming convention. The real topology
        path ``containerlab inspect`` reports is the actual owned-ness check:
        only a lab whose path matches this engine's own workdir convention
        (``self._topo_path(name)``) is retained. A mismatched or missing path
        is simply excluded, never raised on — containerlab's JSON shape can
        carry partial path info for labs this engine has no reason to trust
        anyway. This is the entrypoint used to decide *which* runtime names
        are eligible for orphan cleanup (``reconcile_runtime``); it is
        deliberately narrower than :meth:`_inspect_lab_paths`.
        """
        found = self._inspect_lab_paths()
        return {name: path for name, path in found.items() if path == self._topo_path(name)}

    def _lab_is_deployed(self, instance_name: str) -> bool:
        """Inspect runtime state without trusting the expected topology file."""
        return instance_name in self.inventory()

    def deploy(self, topology_text: str, instance_name: str) -> LabHandle:
        self._require_lab_host()
        if _requires_kvm(topology_text) and not os.path.exists("/dev/kvm"):
            raise RuntimeError("vr-* lab deployment requires /dev/kvm")
        path = self._topo_path(instance_name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(topology_text)
        r = subprocess.run(
            [*_CLAB, "deploy", "-t", path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=_DEPLOY_TIMEOUT_SECONDS,
        )
        if r.returncode != 0:
            raise RuntimeError(f"deploy failed: {r.stderr}")
        nodes, mgmt, kinds = {}, {}, {}
        prefix = f"clab-{instance_name}-"  # containerlab names: clab-<labname>-<node>
        data = json.loads(r.stdout)
        # `containerlab deploy --format json` → {"<labname>": [ {node...} ]}.
        # Be tolerant of a bare list too (older format / unit-test fixtures).
        if isinstance(data, dict):
            items: list = data.get(instance_name) or next(iter(data.values()), [])
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
        self._require_lab_host()
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
        r = subprocess.run(
            ssh,
            capture_output=True,
            text=True,
            timeout=_CHECK_COMMAND_TIMEOUT_SECONDS,
        )
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def destroy(self, instance_name: str) -> None:
        self._require_lab_host()
        path = self._topo_path(instance_name)
        # First deploys and replay after an already-completed destroy may have
        # no topology file. Confirm runtime absence rather than equating a lost
        # file with a destroyed lab: otherwise a live lab can leak silently.
        if not os.path.exists(path):
            # Unfiltered on purpose: the caller already identified this exact
            # instance_name (by row identity) as the one to destroy, so an
            # ownership judgement about the path is not needed here — only
            # reconcile_runtime's "which orphans are ours" decision needs the
            # ownership-filtered inventory().
            discovered_path = self._inspect_lab_paths().get(instance_name)
            if discovered_path is None:
                return
            if not discovered_path:
                raise RuntimeError(
                    f"destroy refused: deployed lab {instance_name!r} has no discoverable topology path"
                )
            path = discovered_path
        r = subprocess.run(
            [*_CLAB, "destroy", "-t", path, "--cleanup"],
            capture_output=True,
            text=True,
            timeout=_DESTROY_TIMEOUT_SECONDS,
        )
        if r.returncode != 0:
            raise RuntimeError(f"destroy failed: {r.stderr}")

    def reset(self, topology_text: str, instance_name: str) -> LabHandle:
        self._require_lab_host()
        self.destroy(instance_name)
        return self.deploy(topology_text, instance_name)

    def exec(self, handle: LabHandle, node: str, command: list) -> ExecResult:
        self._require_lab_host()
        cname = handle.nodes[node]
        r = subprocess.run(
            ["docker", "exec", cname, *command],
            capture_output=True,
            text=True,
            timeout=_CHECK_COMMAND_TIMEOUT_SECONDS,
        )
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def status(self, instance_name: str) -> str:
        self._require_lab_host()
        return "running" if self._lab_is_deployed(instance_name) else "absent"

    def console_target(self, handle: LabHandle, node: str) -> str:
        return handle.nodes[node]
