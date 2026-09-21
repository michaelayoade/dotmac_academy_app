from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
NFT_PATH = ROOT / "deploy" / "academy-lab-ipv6-guard.nft"
UNIT_PATH = ROOT / "deploy" / "academy-lab-ipv6-guard.service"
DOCKER_DROPIN_PATH = ROOT / "deploy" / "academy-lab-ipv6-guard-docker.conf"
RUNBOOK_PATH = ROOT / "deploy" / "LAB_CONSOLE_RECOVERY_ROLLOUT.md"


def _directives(text: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    )


def test_ipv6_guard_is_narrow_idempotent_and_never_owns_forwarding() -> None:
    assert _directives(NFT_PATH.read_text()) == (
        "destroy table inet academy_lab_ipv6_guard",
        "table inet academy_lab_ipv6_guard {",
        "chain prerouting {",
        "type filter hook prerouting priority dstnat - 1; policy accept;",
        "meta nfproto ipv6 fib daddr type local tcp dport 5437 ct state new "
        'counter drop comment "academy-lab: deny new IPv6 to host port 5437"',
        "}",
        "chain input {",
        "type filter hook input priority filter - 1; policy accept;",
        'meta nfproto ipv6 iifname "lo" accept',
        "meta nfproto ipv6 tcp dport { 22, 5437 } ct state new counter drop "
        'comment "academy-lab: deny new IPv6 SSH/Postgres"',
        "}",
        "}",
    )


def test_ipv6_guard_unit_loads_only_the_root_owned_installed_copy() -> None:
    directives = _directives(UNIT_PATH.read_text())
    joined = "\n".join(directives)

    assert directives == (
        "[Unit]",
        "Description=Academy Labs IPv6 host ingress guard",
        "Documentation=https://github.com/michaelayoade/dotmac_academy_app/"
        "blob/main/deploy/LAB_CONSOLE_RECOVERY_ROLLOUT.md",
        "DefaultDependencies=no",
        "Before=network-pre.target docker.service ufw.service nftables.service "
        "firewalld.service shutdown.target",
        "Wants=network-pre.target",
        "Conflicts=shutdown.target ufw.service nftables.service "
        "firewalld.service",
        "AssertHost=academy-labs",
        "AssertPathExists=/etc/nftables.d/academy-lab-ipv6-guard.nft",
        "[Service]",
        "Type=oneshot",
        "ExecStartPre=-/usr/sbin/nft add table inet academy_lab_ipv6_guard",
        "ExecStartPre=/usr/sbin/nft --check --file "
        "/etc/nftables.d/academy-lab-ipv6-guard.nft",
        "ExecStart=/usr/sbin/nft --file "
        "/etc/nftables.d/academy-lab-ipv6-guard.nft",
        "RemainAfterExit=yes",
        "[Install]",
        "WantedBy=sysinit.target",
    )
    assert "User=" not in joined
    assert "Group=" not in joined
    assert "ExecStop=" not in joined
    assert "After=" not in joined
    assert "/home/dotmac/" not in joined


def test_docker_start_gate_does_not_propagate_guard_stop() -> None:
    assert _directives(DOCKER_DROPIN_PATH.read_text()) == (
        "[Unit]",
        "Wants=academy-lab-ipv6-guard.service",
        "After=academy-lab-ipv6-guard.service",
        "[Service]",
        "ExecStartPre=/usr/bin/systemctl --quiet is-active "
        "academy-lab-ipv6-guard.service",
        "ExecStartPre=/usr/sbin/nft list chain inet "
        "academy_lab_ipv6_guard prerouting",
        "ExecStartPre=/usr/sbin/nft list chain inet academy_lab_ipv6_guard input",
    )
    assert "Requires=" not in DOCKER_DROPIN_PATH.read_text()


def test_ipv6_guard_runbook_has_exact_install_and_rollback_boundaries() -> None:
    runbook = RUNBOOK_PATH.read_text()

    assert 'git show "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.nft"' in runbook
    assert (
        'git show "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.service"'
        in runbook
    )
    assert "bash -euo pipefail" in runbook
    assert 'test "$(git rev-parse HEAD)" = "${ACCEPTED_SHA}"' in runbook
    assert 'git diff --quiet "${ACCEPTED_SHA}"' in runbook
    assert 'git diff --cached --quiet "${ACCEPTED_SHA}"' in runbook
    assert runbook.count("deploy/academy-lab-ipv6-guard-docker.conf") >= 5
    assert 'git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.nft"' in runbook
    assert (
        'git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.service"'
        in runbook
    )
    assert (
        'git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard-docker.conf"'
        in runbook
    )
    assert "mktemp -d" in runbook
    assert "sudo install -o root -g root -m 0644" in runbook
    assert "expected_nft_sha" in runbook
    assert "installed_nft_sha" in runbook
    assert "expected_unit_sha" in runbook
    assert "installed_unit_sha" in runbook
    assert "expected_dropin_sha" in runbook
    assert "installed_dropin_sha" in runbook
    assert "| sudo tee" not in runbook
    assert "/etc/nftables.d/academy-lab-ipv6-guard.nft" in runbook
    assert "systemctl enable academy-lab-ipv6-guard.service" in runbook
    assert "systemctl restart academy-lab-ipv6-guard.service" in runbook
    assert "systemctl is-enabled" in runbook
    assert "systemctl is-active" in runbook
    assert "systemctl disable ufw.service" in runbook
    assert "nft list table inet academy_lab_ipv6_guard" in runbook
    assert "systemctl disable academy-lab-ipv6-guard.service" in runbook
    assert "systemctl stop academy-lab-ipv6-guard.service" in runbook
    assert "/etc/systemd/system/docker.service.d/academy-lab-ipv6-guard.conf" in runbook
    assert "systemctl enable ufw.service" in runbook
    assert "nft delete table inet academy_lab_ipv6_guard" in runbook
    assert "ufw status" in runbook
    assert "flush ruleset" not in runbook
