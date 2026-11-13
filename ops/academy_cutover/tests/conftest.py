"""The isolated helper suite has no authority to contact a host or database."""

import os
import socket
import subprocess

import pytest


def _refuse_external_operation(*_args, **_kwargs):
    raise AssertionError("Unmocked network or process operation in cutover-code tests")


@pytest.fixture(autouse=True)
def refuse_external_operations(monkeypatch):
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _refuse_external_operation)
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, _refuse_external_operation)
    monkeypatch.setattr(os, "system", _refuse_external_operation)
