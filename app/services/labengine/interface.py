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
