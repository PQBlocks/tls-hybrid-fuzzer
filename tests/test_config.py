"""Tests for config.py (slice S15).

Strict YAML config loading: unknown keys -> ConfigError naming the key,
type confusion -> ConfigError naming the field, endpoint normalization,
config_version == 1 enforced, no silent coercion.
"""

import pytest

from pqblocks_tlsfuzz.config import FuzzConfig, load_config, _parse_endpoint
from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.corpus import MutationClass
from pqblocks_tlsfuzz.errors import ConfigError


class TestParseEndpoint:
    def test_host_port(self):
        host, port = _parse_endpoint("localhost:8443")
        assert host == "localhost"
        assert port == 8443

    def test_https_prefix_stripped(self):
        host, port = _parse_endpoint("https://example.com:443")
        assert host == "example.com"
        assert port == 443

    def test_http_prefix_stripped(self):
        host, port = _parse_endpoint("http://example.com:8080")
        assert host == "example.com"
        assert port == 8080

    def test_ipv6_bracket_notation(self):
        host, port = _parse_endpoint("[::1]:8443")
        assert host == "::1"
        assert port == 8443

    def test_ipv6_full_address(self):
        host, port = _parse_endpoint("[2001:db8::1]:443")
        assert host == "2001:db8::1"
        assert port == 443

    def test_missing_port_raises(self):
        with pytest.raises(ConfigError, match="missing port"):
            _parse_endpoint("localhost")

    def test_empty_host_raises(self):
        with pytest.raises(ConfigError, match="empty host"):
            _parse_endpoint(":8443")

    def test_bad_port_raises(self):
        with pytest.raises(ConfigError, match="invalid port"):
            _parse_endpoint("localhost:notaport")

    def test_port_out_of_range_raises(self):
        with pytest.raises(ConfigError, match="out of range"):
            _parse_endpoint("localhost:0")
        with pytest.raises(ConfigError, match="out of range"):
            _parse_endpoint("localhost:99999")


class TestFuzzConfigDefaults:
    def test_default_groups_all_six(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert len(cfg.groups) == 6
        assert Group.MLKEM512 in cfg.groups
        assert Group.MLKEM768 in cfg.groups
        assert Group.MLKEM1024 in cfg.groups
        assert Group.X25519MLKEM768 in cfg.groups
        assert Group.SECP256R1MLKEM768 in cfg.groups
        assert Group.SECP384R1MLKEM1024 in cfg.groups

    def test_default_mutation_classes_thirteen(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert len(cfg.mutation_classes) == 13
        assert MutationClass.VALID_CONTROL in cfg.mutation_classes

    def test_default_iterations(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.iterations == 1000

    def test_default_seed(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.seed == 0

    def test_default_timeout(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.timeout_ms == 2000

    def test_default_concurrency(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.concurrency == 4

    def test_default_capture_cap(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.capture_cap_bytes == 65536

    def test_default_config_version(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.config_version == 1


class TestFuzzConfigValidation:
    def test_iterations_zero_raises(self):
        with pytest.raises(ConfigError, match="must be > 0"):
            FuzzConfig(endpoint="localhost:8443", iterations=0)

    def test_iterations_negative_raises(self):
        with pytest.raises(ConfigError, match="must be > 0"):
            FuzzConfig(endpoint="localhost:8443", iterations=-1)

    def test_iterations_exceeds_max_raises(self):
        with pytest.raises(ConfigError, match="exceeds max_iterations"):
            FuzzConfig(endpoint="localhost:8443", iterations=200_000, max_iterations=100_000)

    def test_empty_groups_raises(self):
        with pytest.raises(ConfigError, match="non-empty"):
            FuzzConfig(endpoint="localhost:8443", groups=())

    def test_empty_mutation_classes_raises(self):
        with pytest.raises(ConfigError, match="non-empty"):
            FuzzConfig(endpoint="localhost:8443", mutation_classes=())

    def test_bad_config_version_raises(self):
        with pytest.raises(ConfigError, match="unsupported config_version"):
            FuzzConfig(endpoint="localhost:8443", config_version=2)

    def test_bad_timeout_raises(self):
        with pytest.raises(ConfigError, match="must be > 0"):
            FuzzConfig(endpoint="localhost:8443", timeout_ms=0)

    def test_bad_concurrency_raises(self):
        with pytest.raises(ConfigError, match="must be >= 1"):
            FuzzConfig(endpoint="localhost:8443", concurrency=0)

    def test_bad_capture_cap_raises(self):
        with pytest.raises(ConfigError, match="must be > 0"):
            FuzzConfig(endpoint="localhost:8443", capture_cap_bytes=0)

    def test_endpoint_required(self):
        # Test via load_config with a file missing endpoint
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("groups: [mlkem512]\n")
            f.flush()
            try:
                with pytest.raises(ConfigError, match="missing required key: endpoint"):
                    load_config.__wrapped__(f.name) if hasattr(load_config, "__wrapped__") else load_config(f.name)
            finally:
                os.unlink(f.name)

    def test_unknown_config_key_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("endpoint: localhost:8443\nunknown_key: value\n")
        with pytest.raises(ConfigError, match="unknown config key"):
            load_config(p)

    def test_type_confusion_groups_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("endpoint: localhost:8443\ngroups: 513\n")
        with pytest.raises(ConfigError, match="group must be string"):
            load_config(p)

    def test_type_confusion_mutation_class_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("endpoint: localhost:8443\nmutation_classes: 42\n")
        with pytest.raises(ConfigError, match="mutation class must be string"):
            load_config(p)

    def test_unknown_group_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("endpoint: localhost:8443\ngroups: [not-a-group]\n")
        with pytest.raises(ConfigError, match="unknown group"):
            load_config(p)

    def test_unknown_mutation_class_raises(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("endpoint: localhost:8443\nmutation_classes: [not-a-class]\n")
        with pytest.raises(ConfigError, match="unknown mutation class"):
            load_config(p)


class TestLoadConfigRoundTrip:
    def test_load_config_full_valid(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("""
endpoint: https://example.com:8443
groups: [mlkem512, mlkem768]
iterations: 500
mutation_classes: [truncated, oversized]
seed: 42
timeout_ms: 5000
concurrency: 2
capture_cap_bytes: 32768
max_iterations: 10000
config_version: 1
""")
        cfg = load_config(p)
        assert cfg.host == "example.com"
        assert cfg.port == 8443
        assert cfg.iterations == 500
        assert cfg.seed == 42
        assert cfg.timeout_ms == 5000
        assert cfg.concurrency == 2
        assert cfg.capture_cap_bytes == 32768
        assert cfg.max_iterations == 10000
        assert cfg.config_version == 1

    def test_load_config_utf8_bom(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("\ufeffendpoint: localhost:8443\n", encoding="utf-8-sig")
        cfg = load_config(p)
        assert cfg.host == "localhost"
        assert cfg.port == 8443

    def test_load_config_missing_file_raises(self, tmp_path):
        p = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigError, match="cannot read config file"):
            load_config(p)

    def test_load_config_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("endpoint: [unclosed\n")
        with pytest.raises(ConfigError, match="invalid YAML"):
            load_config(p)

    def test_load_config_root_not_mapping_raises(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="root must be a mapping"):
            load_config(p)


class TestHostPortProperties:
    def test_host_property(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.host == "localhost"

    def test_port_property(self):
        cfg = FuzzConfig(endpoint="localhost:8443")
        assert cfg.port == 8443

    def test_host_property_ipv6(self):
        cfg = FuzzConfig(endpoint="[::1]:8443")
        assert cfg.host == "::1"