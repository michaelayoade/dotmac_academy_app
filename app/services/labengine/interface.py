from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int


class WrongLabHostError(RuntimeError):
    """Raised when a lab engine operation is attempted on a non-lab host."""


@dataclass
class LabHandle:
    instance_name: str
    nodes: dict  # logical node name -> container name
    mgmt: dict  # logical node name -> mgmt IPv4
    kinds: dict  # logical node name -> containerlab kind


class LabEngine(ABC):
    @abstractmethod
    def inventory(self) -> dict[str, str]:
        """Return running lab names mapped to their authoritative topology paths."""
        ...

    @abstractmethod
    def deploy(self, topology_text: str, instance_name: str) -> LabHandle: ...

    @abstractmethod
    def destroy(self, instance_name: str) -> None: ...

    @abstractmethod
    def deploy_if_absent(self, topology_text: str, instance_name: str) -> LabHandle | None:
        """Deploy ``instance_name`` only if it is not already running.

        Observation and mutation happen inside exactly ONE host-lock
        acquisition, atomically — never by composing the public
        :meth:`inventory`/:meth:`deploy` (each of which independently
        acquires and releases its own lock, reopening the exact race this
        primitive exists to close). Returns ``None`` (never calling
        :meth:`deploy`'s underlying mutation) when the runtime is found
        already present; returns the fresh :class:`LabHandle` when the
        precondition held and the deploy actually ran.
        """
        ...

    @abstractmethod
    def destroy_if_present(self, instance_name: str) -> bool:
        """Destroy ``instance_name`` only if it is currently running.

        Same single-lock-acquisition guarantee as :meth:`deploy_if_absent`.
        Returns ``False`` (never calling :meth:`destroy`'s underlying
        mutation) when the runtime is already absent; returns ``True`` when
        the precondition held and the destroy actually ran.
        """
        ...

    @abstractmethod
    def reset(self, topology_text: str, instance_name: str) -> LabHandle: ...

    @abstractmethod
    def exec(self, handle: LabHandle, node: str, command: list) -> ExecResult: ...

    @abstractmethod
    def ssh_exec(
        self,
        handle: LabHandle,
        node: str,
        command: str,
        user: str = "admin",
        password: str = "",
    ) -> ExecResult: ...

    @abstractmethod
    def status(self, instance_name: str) -> str: ...

    @abstractmethod
    def console_target(self, handle: LabHandle, node: str) -> str: ...
