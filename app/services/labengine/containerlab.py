import json
import os
import signal
import subprocess

import yaml

from app.config import settings
from app.services.host_lock import host_lock

from .interface import ExecResult, LabEngine, LabHandle, WrongLabHostError

# containerlab needs root (netns/bridges); the app/worker run unprivileged, so
# invoke it via passwordless sudo. docker exec / ssh stay unprivileged.
_CLAB = ("sudo", "-n", "containerlab")
_INSPECT_TIMEOUT_SECONDS = 60
_DEPLOY_TIMEOUT_SECONDS = 900
_DESTROY_TIMEOUT_SECONDS = 420
_CHECK_COMMAND_TIMEOUT_SECONDS = 480

# How long to wait, after SIGTERM-ing an abandoned command's process group,
# before escalating to SIGKILL. Short on purpose: this only runs once a
# command has already blown its own (much longer) timeout or the call was
# otherwise cancelled, so there is no remaining budget to wait politely.
_GROUP_KILL_GRACE_SECONDS = 5


def _terminate_process_group(proc: "subprocess.Popen[str]") -> None:
    """Best-effort teardown of ``proc`` and every process it spawned.

    Every external command this module runs is started with
    ``start_new_session=True`` (see :func:`_run_contained`), which makes
    ``proc.pid`` the process-group leader's pid too — so signalling the
    *group* via :func:`os.killpg` reaches children the direct child itself
    spawned (e.g. containerlab's own worker subprocesses), not just the
    directly-spawned process. A plain ``proc.kill()`` would only ever reach
    the direct child and would leak any grandchildren that outlive it.

    SIGTERM first, then a bounded grace period, then SIGKILL if the group is
    still alive — the same escalation shape used everywhere else in this
    codebase for "ask nicely, then don't". ``ProcessLookupError`` at either
    signalling step means the group is already gone; that is success, not a
    failure to swallow silently into the caller's real exception.

    Caveat that cannot be verified from this repository: every command here
    is actually invoked as ``sudo -n containerlab ...`` (see ``_CLAB``, and
    ``docker exec``/``ssh`` for the non-containerlab call sites). Whether a
    signal delivered to the ``sudo``-spawned process group actually reaches
    containerlab's own descendants depends on the real lab host's sudoers
    and PAM/session configuration (e.g. whether sudo retains or drops the
    session, and whether it forwards signals to the command it execs). This
    module tests the process-group mechanics themselves against real,
    non-sudo subprocesses; it cannot prove signal propagation through the
    real host's ``sudo -n containerlab`` invocation from a test running here.
    That must be manually verified on the actual lab host as part of this
    rollout.

    The SIGKILL escalation below must never be conditional on whether
    ``proc.wait(timeout=...)`` itself returned successfully.
    ``proc.wait()`` only waits for the direct child — the process-group
    leader — not the whole group. If the direct child dies from SIGTERM
    within the grace period (the common case, since it is never the one
    installing a SIGTERM handler here), ``proc.wait()`` returns
    successfully even though a grandchild the direct child forked may still
    be alive and ignoring or blocking SIGTERM. An early ``return`` in that
    case would skip SIGKILL entirely and leak that grandchild forever, since
    nothing else ever escalates for it. Sending ``SIGKILL`` to a process
    group whose leader has already exited, but that still has surviving
    members, remains safe and correct — the pgid stays valid as long as any
    member is alive. Sending it to an already-fully-empty group just raises
    ``ProcessLookupError``, handled the same as the SIGTERM step above.
    """
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    else:
        try:
            proc.wait(timeout=_GROUP_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait()
    except Exception:  # noqa: S110 - best-effort reap; never mask the caller's real exception
        pass


def _run_contained(
    cmd: list[str] | tuple[str, ...], *, timeout: float
) -> "subprocess.CompletedProcess[str]":
    """Run ``cmd`` in its own process group, guaranteeing group teardown.

    Replaces a bare ``subprocess.run(...)`` at every containerlab/docker/ssh
    call site in this module. The returned value is shaped exactly like
    ``subprocess.run``'s ``CompletedProcess`` — every call site's existing
    ``.returncode``/``.stdout``/``.stderr`` handling, JSON parsing, and
    ``RuntimeError`` messages continue to work unchanged.

    On a timeout, or on any other exception (including cancellation such as
    ``KeyboardInterrupt``) reaching this function while the process is still
    running, the whole process group is torn down (see
    :func:`_terminate_process_group`) before the original exception is
    re-raised unchanged — a ``subprocess.TimeoutExpired`` stays a
    ``TimeoutExpired``, so existing callers' exception-handling contracts do
    not change.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException:
        _terminate_process_group(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


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
    def __init__(
        self,
        workdir: str,
        lab_host_role: str | None = None,
        lock_label: str = "containerlab-engine",
    ):
        self.workdir = workdir
        self.lab_host_role = lab_host_role if lab_host_role is not None else settings.lab_host_role
        # Identifies this engine's caller (worker vs. reconciler) in the host
        # lock file / contention messages — see app.services.host_lock.
        self.lock_label = lock_label

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
        result = _run_contained(
            [*_CLAB, "inspect", "--all", "--format", "json"],
            timeout=_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise RuntimeError(f"inspect failed: {result.stderr}")
        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("inspect returned invalid JSON") from exc

    def _inspect_lab_paths_unlocked(self) -> dict[str, str]:
        """Every containerlab-reported lab name -> its real topology path.

        Unfiltered by design: a caller that already knows (by row identity)
        which specific instance it means to act on — e.g. ``_destroy_unlocked``
        below, recovering the real path for a lab whose expected topology
        file went missing — needs whatever path containerlab actually
        reports, not an ownership judgement about it. :meth:`inventory` is
        the ownership-filtered view built on top of this for callers (like
        ``reconcile_runtime``) that must decide *which* names are Academy's
        to manage in the first place.

        Unlocked: callers must already hold ``host_lock``. Never call this
        (or any other ``_*_unlocked`` helper) from a public method other than
        the one already holding the lock — public methods must not call each
        other, since a second ``host_lock`` acquisition within the same
        process on a fresh fd does not merge with the first and instead
        fails as if a different process held it.
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

    def _inventory_unlocked(self) -> dict[str, str]:
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
        deliberately narrower than :meth:`_inspect_lab_paths_unlocked`.

        Unlocked — see :meth:`_inspect_lab_paths_unlocked`.
        """
        found = self._inspect_lab_paths_unlocked()
        return {name: path for name, path in found.items() if path == self._topo_path(name)}

    def inventory(self) -> dict[str, str]:
        self._require_lab_host()
        with host_lock(self.lock_label, directory=self.workdir):
            return self._inventory_unlocked()

    def _lab_is_deployed_unlocked(self, instance_name: str) -> bool:
        """Inspect runtime state without trusting the expected topology file.

        Unlocked — see :meth:`_inspect_lab_paths_unlocked`.
        """
        return instance_name in self._inventory_unlocked()

    def _deploy_unlocked(self, topology_text: str, instance_name: str) -> LabHandle:
        """Unlocked — see :meth:`_inspect_lab_paths_unlocked`.

        The KVM fail-closed check lives here, not only in the public
        ``deploy()`` wrapper, so every caller of this helper — including
        ``reset()``, which calls it directly to avoid a nested lock
        acquisition — gets it automatically rather than relying on each
        caller to have remembered its own copy.
        """
        if _requires_kvm(topology_text) and not os.path.exists("/dev/kvm"):
            raise RuntimeError("vr-* lab deployment requires /dev/kvm")
        path = self._topo_path(instance_name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(topology_text)
        r = _run_contained(
            [*_CLAB, "deploy", "-t", path, "--format", "json"],
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

    def deploy(self, topology_text: str, instance_name: str) -> LabHandle:
        self._require_lab_host()
        # The KVM check itself lives in _deploy_unlocked (see its docstring)
        # so reset() gets it too without a second, driftable copy here.
        with host_lock(self.lock_label, directory=self.workdir):
            return self._deploy_unlocked(topology_text, instance_name)

    def _ssh_exec_unlocked(
        self,
        handle: LabHandle,
        node: str,
        command: str,
        user: str,
        password: str,
    ) -> ExecResult:
        """Unlocked — see :meth:`_inspect_lab_paths_unlocked`."""
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
        r = _run_contained(ssh, timeout=_CHECK_COMMAND_TIMEOUT_SECONDS)
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def ssh_exec(
        self,
        handle: LabHandle,
        node: str,
        command: str,
        user: str = "admin",
        password: str = "",
    ) -> ExecResult:
        self._require_lab_host()
        with host_lock(self.lock_label, directory=self.workdir):
            return self._ssh_exec_unlocked(handle, node, command, user, password)

    def _destroy_unlocked(self, instance_name: str) -> None:
        """Unlocked — see :meth:`_inspect_lab_paths_unlocked`."""
        path = self._topo_path(instance_name)
        # First deploys and replay after an already-completed destroy may have
        # no topology file. Confirm runtime absence rather than equating a lost
        # file with a destroyed lab: otherwise a live lab can leak silently.
        if not os.path.exists(path):
            # Unfiltered on purpose: the caller already identified this exact
            # instance_name (by row identity) as the one to destroy, so an
            # ownership judgement about the path is not needed here — only
            # reconcile_runtime's "which orphans are ours" decision needs the
            # ownership-filtered inventory(). But an exact-name collision is
            # still (however unlikely, given the name embeds tenant/person/
            # activity UUID fragments) not ruled out by name alone, so the
            # discovered path must match the one this engine would itself
            # have written before it's trusted — anything else is refused
            # rather than silently destroyed at an unverified location.
            discovered_path = self._inspect_lab_paths_unlocked().get(instance_name)
            if discovered_path is None:
                return
            if discovered_path != path:
                raise RuntimeError(
                    f"destroy refused: deployed lab {instance_name!r} was inspected at "
                    f"{discovered_path!r}, not the expected {path!r}"
                )
        r = _run_contained(
            [*_CLAB, "destroy", "-t", path, "--cleanup"],
            timeout=_DESTROY_TIMEOUT_SECONDS,
        )
        if r.returncode != 0:
            raise RuntimeError(f"destroy failed: {r.stderr}")

    def destroy(self, instance_name: str) -> None:
        self._require_lab_host()
        with host_lock(self.lock_label, directory=self.workdir):
            self._destroy_unlocked(instance_name)

    def reset(self, topology_text: str, instance_name: str) -> LabHandle:
        self._require_lab_host()
        # Held for the whole destroy+deploy pair so no other host operation
        # can interleave between them — calling the public destroy()/deploy()
        # in sequence would each acquire and fully release the lock, leaving
        # a window between the two where another process could run.
        with host_lock(self.lock_label, directory=self.workdir):
            self._destroy_unlocked(instance_name)
            return self._deploy_unlocked(topology_text, instance_name)

    def _exec_unlocked(self, handle: LabHandle, node: str, command: list) -> ExecResult:
        """Unlocked — see :meth:`_inspect_lab_paths_unlocked`."""
        cname = handle.nodes[node]
        r = _run_contained(
            ["docker", "exec", cname, *command],
            timeout=_CHECK_COMMAND_TIMEOUT_SECONDS,
        )
        return ExecResult(stdout=r.stdout, stderr=r.stderr, exit_code=r.returncode)

    def exec(self, handle: LabHandle, node: str, command: list) -> ExecResult:
        self._require_lab_host()
        with host_lock(self.lock_label, directory=self.workdir):
            return self._exec_unlocked(handle, node, command)

    def status(self, instance_name: str) -> str:
        self._require_lab_host()
        with host_lock(self.lock_label, directory=self.workdir):
            return "running" if self._lab_is_deployed_unlocked(instance_name) else "absent"

    def console_target(self, handle: LabHandle, node: str) -> str:
        return handle.nodes[node]
