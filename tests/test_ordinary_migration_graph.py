"""Hosted installed-owner graph and actual PostgreSQL connection canaries.

Not executed locally. CI supplies the complete source, installed distributions,
preprovisioned roles/catalog, and a separate disposable migration database.
These tests do not perform replay, identity import or head stamping.
"""

import ast
import hashlib
import os
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest
from dotmac_kernel.modules import ModuleRegistry
from dotmac_kernel.prerequisites import installed_bindings, resolve_depends_on
from sqlalchemy import create_engine, event, text

from alembic import command
from alembic.script import ScriptDirectory
from app.config import settings
from app.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS
from app.migration_graph import ordinary_migration_config
from app.owner_composition import compose_migration_owner_declarations


def test_graph_commands_have_complete_config_and_bindings_before_env(monkeypatch):
    # An env.py dependency would make these graph-only commands fail.
    import alembic.script.base

    def refuse_env(*args, **kwargs):
        pytest.fail("graph commands must not run env.py")

    monkeypatch.setattr(alembic.script.base.ScriptDirectory, "run_env", refuse_env)
    config = ordinary_migration_config()
    config.stdout = StringIO()
    scripts = ScriptDirectory.from_config(config)
    registry = ModuleRegistry(compose_migration_owner_declarations())
    assert config.attributes["academy_migration_registry"].startup_order() == registry.startup_order()
    assert len(scripts.version_locations) == len(registry.namespaces().owners())
    assert tuple(installed_bindings()) == tuple(sorted(ASSEMBLY_PREREQUISITE_BINDINGS, key=lambda b: b.prerequisite))
    for binding in ASSEMBLY_PREREQUISITE_BINDINGS:
        assert binding.provider_owner == "kernel"
        assert scripts.get_revision(binding.provider_revision) is not None
        assert binding.provider_revision in resolve_depends_on((binding.prerequisite,))
    assert set(config.attributes["academy_migration_locations"]) == set(map(Path, scripts.version_locations))
    assert (Path(__file__).resolve().parents[1] / "alembic" / "versions").resolve() not in config.attributes["academy_migration_locations"]
    command.heads(config)
    command.history(config)
    command.show(config, "a003_account_token_identity")
    assert "a003_account_token_identity" in config.stdout.getvalue()
    command.show(config, "a004_retained_learning_refs")
    assert "a004_retained_learning_refs" in config.stdout.getvalue()
    retained = scripts.get_revision("a004_retained_learning_refs")
    assert retained.down_revision == "a003_account_token_identity"
    assert retained.dependencies == "lr_0007_enrollment_state_policy"
    assert scripts.get_revision("lr_0007_enrollment_state_policy") is not None
    command.show(config, "a005_erp_completion_checkpoint")
    assert "a005_erp_completion_checkpoint" in config.stdout.getvalue()
    checkpoint = scripts.get_revision("a005_erp_completion_checkpoint")
    assert checkpoint.down_revision == "a004_retained_learning_refs"
    assert checkpoint.dependencies is None
    command.show(config, "a006_lab_claim_lease")
    assert "a006_lab_claim_lease" in config.stdout.getvalue()
    lab_claim = scripts.get_revision("a006_lab_claim_lease")
    assert lab_claim.down_revision == "a005_erp_completion_checkpoint"
    assert lab_claim.dependencies is None


def test_disabled_owner_still_contributes_exact_location():
    from dotmac_kernel.migrations import versions_dir as kernel_versions
    from dotmac_learning.migrations import versions_dir as learning_versions

    from app.assembly import assembly
    from app.migration_graph import IDENTITY_VERSIONS, build_migration_config

    locators = {"kernel": kernel_versions, "learning": learning_versions, "assembly": lambda: IDENTITY_VERSIONS}
    disabled = replace(assembly, disabled_modules=frozenset({"learning", "academy"}))
    actual = build_migration_config(disabled, owner_locations=locators)
    ordinary = ordinary_migration_config()
    assert actual.get_main_option("version_locations") == ordinary.get_main_option("version_locations")
    for changed in ({key: value for key, value in locators.items() if key != "learning"}, {**locators, "invented": kernel_versions}):
        with pytest.raises(ValueError, match="every installed owner exactly"):
            build_migration_config(disabled, owner_locations=changed)


@pytest.fixture
def migration_connection():
    assert os.environ.get("CI") == "true", "hosted CI only"
    url = os.environ.get("ACADEMY_MIGRATION_GRAPH_DATABASE_URL")
    assert url, "CI must provision a dedicated migration catalog database"
    engine = create_engine(url, hide_parameters=True)
    try:
        with engine.connect() as connection, connection.begin():
            yield connection
    finally:
        engine.dispose()


def test_actual_supplied_connection_preserves_root_and_has_no_engine_or_commit(migration_connection, monkeypatch):
    connection = migration_connection
    root = connection.get_transaction()
    login, effective = connection.execute(text("SELECT session_user, current_user")).one()
    monkeypatch.setattr(settings, "migration_login_role", login)
    monkeypatch.setattr(settings, "migration_effective_role", effective)
    events = []
    event.listen(connection, "commit", lambda conn: events.append("commit"))
    event.listen(connection, "rollback", lambda conn: events.append("rollback"))

    def refuse_engine(*args, **kwargs):
        pytest.fail("supplied connection branch constructed an engine")

    monkeypatch.setattr("sqlalchemy.create_engine", refuse_engine)
    config = ordinary_migration_config()
    config.attributes["connection"] = connection
    command.current(config)
    assert connection.get_transaction() is root and root.is_active
    assert not connection.closed and not events


def test_actual_supplied_connection_denies_unconfigured_or_wrong_role(migration_connection, monkeypatch):
    for login, effective in (("", ""), ("unconfigured_migration_login", "unconfigured_migration_effective")):
        monkeypatch.setattr(settings, "migration_login_role", login)
        monkeypatch.setattr(settings, "migration_effective_role", effective)
        config = ordinary_migration_config()
        config.attributes["connection"] = migration_connection
        root = migration_connection.get_transaction()
        with pytest.raises(ValueError, match="migration"):
            command.current(config)
        assert migration_connection.get_transaction() is root and root.is_active
        assert not migration_connection.closed


def test_offline_adoption_refused():
    config = ordinary_migration_config()
    with pytest.raises(ValueError, match="offline adoption is unsupported"):
        command.upgrade(config, "heads", sql=True)


def test_feature_route_order_is_byte_source_equivalent_to_prior_declaration():
    source = Path(__file__).resolve().parents[1] / "app" / "assembly.py"
    tree = ast.parse(source.read_text())
    declaration = next(
        node.value for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "academy_feature" for target in node.targets)
    )
    assert isinstance(declaration.func, ast.Name) and declaration.func.id == "replace"
    expected = {
        "routers": "f224fca0ac3f83f623828e23527d2aa1802dfccb1a4b9ca45ecc39439a8b7363",
        "web_routers": "17c4bde90bafda08228acc49ec455844694fdc07c1b33f99edd7d1da94a6c19f",
    }
    observed = {
        keyword.arg: hashlib.sha256(ast.dump(keyword.value, include_attributes=False).encode()).hexdigest()
        for keyword in declaration.keywords
    }
    assert observed == expected


HISTORICAL_SHA256 = {'0005_labs.py': '1febeebbae42ab1aa66f6e0a3648fc5b84b53d53644ef7e19a7779b0bb2e8404', '0006_platform_settings.py': '638f6cbf8e210aee9e56f95740fec16c32d5bea4d5280beac8ca32c7f73d10d9', '0007_person_profile.py': '5ba2d46aa152ce4531289fcdfe500a1de5195d606fab6d480bb258e1efd2b40a', '0008_course_offerings.py': 'e818b9f05c60067b25999a9a3494aa4d7d26ea3a8cebcc598c0851aaaeedd548', '0009_offering_window.py': '4376d5c7b121e84ef671829a0293de3e95d6ea6772dbbdb9f7303bf39f632772', '0010_course_completions.py': '71a5685aaee0de29b84b10c4b915cae9a28b81d896b2514c6d53232b9c5d497b', '0011_certificates.py': '971d76b1e8ba215153639992f0e4f065ef39205bfeae84137786d631d256921f', '0012_offering_activities.py': 'b3980420b3b5bdbedf497f4725f3081c551decf3437ea224e52031fab90610d0', '0013_course_prerequisites.py': '76150f830515a1e75f3e355364fd9f5c49e33d08218b0be14a349d775c611af8', '0014_account_tokens.py': 'bbe1d5ab93f59424b8183b997ad1541eaaeb161f776f1ca8b6ec2e4559536996', '0015_person_status.py': 'f3157118ce9e4dfbe85fa6141f9dc3d9e900552a90d81af168e11ee48d6479c8', '0016_activity_max_attempts.py': '7c26ff37a40b81f662a49c6788bfbdf1889e4cd2b8de7f86eff57e457c44f2bd', '0017_activity_grading.py': '7623567feb5649b0655977ff9bcab51f5386f453839989110a1d079d928aca03', '0018_course_status.py': 'c0e34afcfd3498b9a54db72386d6ca0d08fc91266218bc0612c64291452dc911', '0019_chapter_body_md.py': '269908422fbe6e9c520ec3f3593b911065dc0912a4c831266d4a189bc1a0d152', '0020_activity_attempts.py': '81adde48bcd94469ecb02300d714c11b778a51cf4fdb3988b4336ced9824325f', '0020_notifications.py': 'f3bf479ae08977b1b38286fa5b0b143dd394d13f298c39494a031a5a25c40f33', '0021_announcements.py': '0b77f7ebb01d2eba8fb10ad25c94a40d280b6b07ad210594cba49fe697528c7e', '0022_activity_weight.py': '9abfce03c6dbbc9ba2f0206a560ba864be0bfc8da1c6e04259a737fcdc9c47dc', '0023_merge_gaps_attempts_heads.py': '47e10f287a34d7e2af369deaf8863f3468ac8e8875c19e03faad7eefa470932b', '0024_chapter_reads.py': '0d187a865509021e2152e1c06ff5ef6e9a47e4c1400874718870de542d9a7bee', '0025_admissions.py': 'e8e5ab8015b353f67b6d4e9324cfb054d4c6498f8b58ef8f1c633e2da55c63a7', '0026_class_sessions.py': '5a41c425aa7c3064432d43db5ce1bea9fc39874816af60fcc01715e18357e82b', '0027_assessment_mode.py': '7981defee43ef9398d36d64e02f69b675aa3657e73a2b7d5ae22e61d31082726', '0028_onboarding_tasks.py': '8f07415391080426dd6f645cbcb9d1a7f3dc89d683f7cd432257860017823a78', '0029_completion_erp_synced.py': 'b81a71ef6378ae84a7135f4c0d21f532230b3546d3dc9f3b5b9df2a16bb9c436', '0030_entrance_assessment.py': 'a4eb78a5115b18711506cb6db722c31e9c60b0875dd776e76e5ed7c367c1b580', '0031_applicant_assessment_token.py': '300e85d6eee504a76afd4aa1a321b4fb732766c69a7c4219b0a2c6627e60d38c', '0032_entrance_timer.py': '54e3794198ff270344a858d8a0a012038e841768765f9ce8105a85a5981e879b', '0033_tenant_default_entrance.py': 'e00d7d823b9c4843b1b3e7e3ec6174b1785e88bcd3ae4b0f6ef63a9bd97c875e', '0036_tracks.py': '1c8297a03559f09f8ddda42b21255587276a36f933f13d0bff2913ced053be2a', '0037_pause_entrance_timer.py': 'f44ee8eb3b5e1fa408acc21a120a3c71d6b24391b136f9019cf4f52b59973bec', '0038_onboarding_token.py': 'def53e06c77a7e64d06a0b2d9d7dfde9a802104edab3142b6482f2de586a9424', '0039_auto_accept_threshold.py': '3729acc0356709216c2f92983ea350a45b356b13970a172eef308dce430446da', '0040_merge_tracks_admissions.py': 'bf2090ebe86706087c17a3a2bdc903c284b97545aa751fcbbe8d6b63e9eb9182', '0041_review_remediation.py': '04f1566ea2ab508eea96207652917a3b6ce5d278f7cefc4f99f94224a0b93060', '0042_course_listed.py': '3def18d99d255ab0cd13adb66c5eb6023e1ae061ad0fedc47c74ed46199eb68e', '0043_bookmarks_notes.py': '07515bb75f3d652b0b3029c560b2edcfc5fc72c3ce42bb825cc74084db3cc546', '0044_reminders.py': '04d7532c390e95c4d88d0ebf69fe92d681450b643d94d131e4f55768bf3153e3', '0045_learning_events.py': '870e0345e74481a4451d487afdcf7e40abc2b10ba3e114a68089448b3ef5d570', '0046_success_queue.py': '25d94ccc54d14ff95861345d0b15a20e6823b03b1899b40d2a57d14490809199', '0047_learning_event_dedup.py': '4f06d99be151b6a97d47951e85e06176c6dc4ab54df4c69c8e9aece8a2751dd8', '0048_subtopic_reads.py': '218a2e066370724baca846429f3ce89d7723f9d0cba9e0b3883bac25ce5721d5', '0049_enrollment_audience.py': '211b36f1b8055304c2aa84f2c3c37856011a0447211754ca3eb555c5d30456f7', '0050_enrollment_access_extension.py': '589c23d4078e5ee08476614987eb2a82fa1b23ef66954712ad07b723388ca577', '0051_attempt_grants.py': 'bb787257721d4521d71b8823e2ffcdf142035c6269a2550f0e8e9865c8482338', '0052_erp_applicant_assessments.py': 'e7c67dbcc7ff2dc6eb59d2334f3a3c73eda89478bc7733cdb1bcfa46a1da1d9a', '0053_entrance_defaults_table.py': 'd9a77e4084e5fbf68d74b61b278738396b3b1156ec8720cbe3976bdb4242f71d', '0054_lab_instructions_md.py': 'ce94d46eab8f7a0b5ce8e109291a66ca964fa9fe71418080e6721ffd92276bf5', '0055_lab_operations.py': '5f1befb9f90c0db8fe3944c545e5802dd8eeb21eea9b55868311a835833905c5', '0056_lab_instance_worker_grants.py': 'fd75319dd804b8f0a388d0fde8f164421503d8e26b695c1c4459bed519e52aa7', '0057_lab_instance_name_unique.py': 'a62e6765da087bff95c0f23431ef3e6b11a6eca9bde45c357b2ac644175bc849', '0058_lab_runtime_presence.py': '90b055ad7a308bb2a4f4413e54d1d73e4ab97fe8da41c07f59c1bd0d76fe6e49', '0059_lab_claim_owner.py': 'a1d08823ab75bc8049dc86e1738fb52ae25b71e43f5f3d48b4134bdfa9810f1e', '0060_lab_conditional_ops.py': 'a9d670de50e1c9d8d0048edcf6c98524372fe6b562e27278a3bf37612daa5937', '0061_lab_completion_grants.py': 'e2da178268685378e46239391f0455cfb3937f1ee632254d9baf0600d31b3f65', '20260504_0001_initial_tenant_schema.py': '33f9569bccc1562a2973df75e597332bb13b3003bab4d1815943e6cbee3eba3e', '20260626_0002_courses.py': '89eae42c361a70b81bd2416b9c1338072b4be67788e6dfe76137e12f31fb53ca', '20260626_0003_cohorts.py': 'eb479ff244a1d5b65f395a6c1f188c079a0f0e9db3f72e4d6dc253cb82cd06bb', '20260626_0004_assessment.py': 'a118b1658abced245f04994afc0989ead3c203dc93c71a48d99bfd5c2008b5eb', '20260711_0034_entrance_resilience.py': '0b14733170a5c9cb84edb6be6e1c57e703851537f6447aa173bd2046e80b2554', '20260711_0035_applicant_profile.py': 'd6bcfc0f7932cdb1aa8df3f2608e3a4911e32673512da3e3ea2533ed7d82fdc0'}

# Post-adoption successors of the frozen 0061 head (444ce556 blobs for 0062-0064,
# the renumbered applicant bank version pin for 0065). Pinned exactly.
SUCCESSOR_SHA256 = {
    "0062_lab_template_access.py": "7311f8e81a271d7dc4b071a16905fb2c87c9f7466c6051897c65cc9ed7b7a3ad",
    "0063_lab_console_activity.py": "15cd8b678ad53e6175e164964d391af3066c683598c5f048e19408eab19f6c04",
    "0064_facilitator_nominations.py": "97bc33859c9bf6599e4e1be6ce94c5fcc5dc55f192f0abfa5bfb8c8230d6e559",
    "0065_applicant_bank_version_pin.py": "5c50301d9c7a73eedf7193839c9d0e804af1a401bb85867cfdd6381b3a53639c",
}


def _sha256_by_name(directory):
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.glob("*.py")
        if path.name != "__init__.py"
    }


def test_all_62_frozen_history_bytes_are_conserved_in_complete_hosted_source():
    versions = Path(__file__).resolve().parents[1] / "alembic" / "versions"
    assert not set(HISTORICAL_SHA256) & set(SUCCESSOR_SHA256)
    live = _sha256_by_name(versions)
    assert set(live) == set(HISTORICAL_SHA256) | set(SUCCESSOR_SHA256)
    assert {name: live[name] for name in HISTORICAL_SHA256} == HISTORICAL_SHA256
    assert {name: live[name] for name in SUCCESSOR_SHA256} == SUCCESSOR_SHA256


def test_frozen_fixture_inventory_is_exactly_the_62_historical_files():
    fixture = Path(__file__).resolve().parent / "fixtures" / "kernel_identity_entry" / "alembic" / "versions"
    assert _sha256_by_name(fixture) == HISTORICAL_SHA256
    assert len(HISTORICAL_SHA256) == 62


def test_autogenerate_metadata_gap_is_explicit_before_database_entry():
    from types import SimpleNamespace

    config = ordinary_migration_config()
    config.cmd_opts = SimpleNamespace(autogenerate=True)
    with pytest.raises(ValueError, match="canonical owner metadata contains copied identity references"):
        command.current(config)
