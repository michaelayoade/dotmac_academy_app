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
        "Conflicts=shutdown.target",
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
    assert (
        'git diff --quiet "${ACCEPTED_SHA}" -- '
        "deploy/academy-lab-ipv6-guard.nft "
        "deploy/academy-lab-ipv6-guard.service "
        "deploy/academy-lab-ipv6-guard-docker.conf" in runbook
    )
    assert (
        'git diff --cached --quiet "${ACCEPTED_SHA}" -- '
        "deploy/academy-lab-ipv6-guard.nft "
        "deploy/academy-lab-ipv6-guard.service "
        "deploy/academy-lab-ipv6-guard-docker.conf" in runbook
    )
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
    assert "systemctl disable --now ufw.service" in runbook
    assert "systemctl mask ufw.service nftables.service firewalld.service" in runbook
    assert "nft list table inet academy_lab_ipv6_guard" in runbook
    assert "systemctl disable academy-lab-ipv6-guard.service" in runbook
    assert "systemctl stop academy-lab-ipv6-guard.service" in runbook
    assert "/etc/systemd/system/docker.service.d/academy-lab-ipv6-guard.conf" in runbook
    assert "systemctl unmask ufw.service nftables.service firewalld.service" in runbook
    assert "systemctl enable --now ufw.service" in runbook
    assert "containerlab inspect" in runbook
    assert "docker ps --quiet | wc -l" in runbook
    assert runbook.count("Docker-container count") == 2
    assert "nft delete table inet academy_lab_ipv6_guard" in runbook
    assert "ufw status" in runbook
    assert "flush ruleset" not in runbook


def _ipv6_verification_contract(runbook: str) -> str:
    start = "6. Reconfirm IPv4 SSH and outbound IPv6"
    end = "\n\nThe guard deliberately"
    return " ".join((start + runbook.split(start, 1)[1].split(end, 1)[0]).split())


IPV6_VERIFICATION_CONTRACT = " ".join(
    """6. Reconfirm IPv4 SSH and outbound IPv6, then prove both IPv6 ingress
    layers independently. Record read-only counter values before and after each
    test; do not reset counters or mutate either firewall. From an explicitly
    named, off-network IPv6-capable host, attempt new TCP connections to ports 22
    and 5437. Neither may connect, and both attempts must increase the exact,
    uniquely labeled Garki-core edge rule counter `SEC-IPv6-20260921 deny
    unsolicited new to Dotmac-Labs`. Because that upstream `/128` forward-drop
    consumes the packets, these attempts are not expected to increase either
    counter in the Dotmac Labs host guard. A local `no route` result is
    inconclusive and does not prove the edge layer. 7. Without disabling,
    deleting, flushing, replacing, or otherwise changing the Garki-core edge
    rule, exercise the Dotmac Labs host guard through an explicitly named safe
    directly connected or router-originated IPv6 path. The path must reach the
    lab host while leaving the edge rule enabled. New TCP attempts to port 22
    must fail and increase the host `input` counter; new TCP attempts to port
    5437 must fail and increase the host `prerouting` counter. For this recorded
    Dotmac Labs topology, absence of either expected layer is a stop condition;
    refuse any ambiguous result and never treat one layer's counter as proof of
    the other. A separately documented single-layer topology must name and prove
    its applicable direct counter. ICMPv6 and established return traffic remain
    permitted, and retain the existing IPv4 and outbound-IPv6 checks.""".split()
)


def test_ipv6_guard_runbook_requires_exact_independent_proof_contract() -> None:
    assert (
        _ipv6_verification_contract(RUNBOOK_PATH.read_text())
        == IPV6_VERIFICATION_CONTRACT
    )


def test_ipv6_guard_runbook_contract_detects_a_planted_semantic_weakening() -> None:
    planted = RUNBOOK_PATH.read_text().replace(
        "TCP attempts to port 22 must fail",
        "TCP attempts to port 22 may connect",
        1,
    )
    assert _ipv6_verification_contract(planted) != IPV6_VERIFICATION_CONTRACT
