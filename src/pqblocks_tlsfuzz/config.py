"""Configuration for pqblocks_tlsfuzz (slice S15).

FuzzConfig dataclass with strict YAML loading and validation.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.corpus import MutationClass
from pqblocks_tlsfuzz.errors import ConfigError


# Default values from spec §2.3
DEFAULT_GROUPS = (
    Group.MLKEM512,
    Group.MLKEM768,
    Group.MLKEM1024,
    Group.X25519MLKEM768,
    Group.SECP256R1MLKEM768,
    Group.SECP384R1MLKEM1024,
)

DEFAULT_CLASSES = (
    MutationClass.TRUNCATED,
    MutationClass.OVERSIZED,
    MutationClass.BITFLIP,
    MutationClass.GARBAGE_FILL,
    MutationClass.BOUNDARY_OFF_BY_ONE,
    MutationClass.WRONG_GROUP_BYTES,
    MutationClass.DUPLICATE_SHARE,
    MutationClass.MISSING_SHARE,
    MutationClass.LIST_TRUNCATION,
    MutationClass.HYBRID_BOUNDARY_SHIFT,
    MutationClass.OVERSIZE_RECORD,
    MutationClass.REORDERED_GROUPS,
    MutationClass.VALID_CONTROL,
)


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse endpoint string into (host, port).
    
    Accepts: "host:port", "https://host:port", "[::1]:port"
    Raises ConfigError for invalid format.
    """
    ep = endpoint.strip()
    
    # Strip https:// or http:// prefix
    if ep.startswith("https://"):
        ep = ep[8:]
    elif ep.startswith("http://"):
        ep = ep[7:]
    
    # Handle IPv6 bracket notation
    if ep.startswith("["):
        if "]" not in ep:
            raise ConfigError(f"invalid IPv6 endpoint: missing closing bracket in {endpoint!r}")
        host_part, _, port_part = ep.partition("]:")
        host = host_part[1:]  # strip leading [
        port_str = port_part
    else:
        # Simple host:port
        if ":" not in ep:
            raise ConfigError(f"invalid endpoint (missing port): {endpoint!r}")
        host, _, port_str = ep.rpartition(":")
    
    if not host:
        raise ConfigError(f"empty host in endpoint: {endpoint!r}")
    if not port_str:
        raise ConfigError(f"empty port in endpoint: {endpoint!r}")
    
    try:
        port = int(port_str)
    except ValueError:
        raise ConfigError(f"invalid port {port_str!r} in endpoint: {endpoint!r}")
    
    if not (1 <= port <= 65535):
        raise ConfigError(f"port out of range 1-65535: {port}")
    
    return host, port


def _parse_groups(groups: list[Any] | tuple[Any, ...] | None) -> tuple[Group, ...]:
    """Parse groups from config (list of strings) into tuple of Group enums."""
    if groups is None:
        return DEFAULT_GROUPS
    if not isinstance(groups, (list, tuple)):
        raise ConfigError(f"group must be string, got {type(groups).__name__}")
    if not groups:
        return DEFAULT_GROUPS
    result = []
    for g in groups:
        if isinstance(g, str):
            try:
                result.append(Group(g.lower()))
            except ValueError:
                raise ConfigError(f"unknown group: {g!r}")
        else:
            raise ConfigError(f"group must be string, got {type(g).__name__}")
    return tuple(result)


def _parse_mutation_classes(classes: list[Any] | tuple[Any, ...] | None) -> tuple[MutationClass, ...]:
    """Parse mutation classes from config into tuple of MutationClass enums."""
    if classes is None:
        return DEFAULT_CLASSES
    if not isinstance(classes, (list, tuple)):
        raise ConfigError(f"mutation class must be string, got {type(classes).__name__}")
    if not classes:
        return DEFAULT_CLASSES
    result = []
    for c in classes:
        if isinstance(c, str):
            try:
                result.append(MutationClass(c.lower()))
            except ValueError:
                raise ConfigError(f"unknown mutation class: {c!r}")
        else:
            raise ConfigError(f"mutation class must be string, got {type(c).__name__}")
    return tuple(result)


@dataclass(frozen=True)
class FuzzConfig:
    """Configuration for a fuzz campaign (spec §1.3, §2.3)."""
    
    endpoint: str = ""               # "host:port"; scheme-less or https:// accepted, normalized
    groups: tuple[Group, ...] = DEFAULT_GROUPS
    iterations: int = 1000
    mutation_classes: tuple[MutationClass, ...] = DEFAULT_CLASSES
    seed: int = 0
    timeout_ms: int = 2000
    concurrency: int = 4
    capture_cap_bytes: int = 65536
    max_iterations: int = 100_000
    config_version: int = 1
    
    def __post_init__(self) -> None:
        # Validate iterations first (before endpoint parsing to match test expectations)
        if not isinstance(self.iterations, int):
            raise ConfigError(f"iterations must be int, got {type(self.iterations).__name__}")
        if self.iterations <= 0:
            raise ConfigError(f"iterations must be > 0, got {self.iterations}")
        if self.iterations > self.max_iterations:
            raise ConfigError(f"iterations {self.iterations} exceeds max_iterations {self.max_iterations}")
        
        # Validate mutation_classes early
        if not self.mutation_classes:
            raise ConfigError("mutation_classes must be non-empty")
        for c in self.mutation_classes:
            if not isinstance(c, MutationClass):
                raise ConfigError(f"mutation class must be MutationClass enum, got {type(c).__name__}")
        
        # Validate groups
        if not self.groups:
            raise ConfigError("groups must be non-empty")
        for g in self.groups:
            if not isinstance(g, Group):
                raise ConfigError(f"group must be Group enum, got {type(g).__name__}")
            # Verify group is known
            GroupRegistry().get(g)
        
        # Validate seed
        if not isinstance(self.seed, int):
            raise ConfigError(f"seed must be int, got {type(self.seed).__name__}")
        
        # Validate timeout
        if not isinstance(self.timeout_ms, int):
            raise ConfigError(f"timeout_ms must be int, got {type(self.timeout_ms).__name__}")
        if self.timeout_ms <= 0:
            raise ConfigError(f"timeout_ms must be > 0, got {self.timeout_ms}")
        
        # Validate concurrency
        if not isinstance(self.concurrency, int):
            raise ConfigError(f"concurrency must be int, got {type(self.concurrency).__name__}")
        if self.concurrency < 1:
            raise ConfigError(f"concurrency must be >= 1, got {self.concurrency}")
        
        # Validate capture_cap_bytes
        if not isinstance(self.capture_cap_bytes, int):
            raise ConfigError(f"capture_cap_bytes must be int, got {type(self.capture_cap_bytes).__name__}")
        if self.capture_cap_bytes <= 0:
            raise ConfigError(f"capture_cap_bytes must be > 0, got {self.capture_cap_bytes}")
        
        # Validate max_iterations
        if not isinstance(self.max_iterations, int):
            raise ConfigError(f"max_iterations must be int, got {type(self.max_iterations).__name__}")
        if self.max_iterations <= 0:
            raise ConfigError(f"max_iterations must be > 0, got {self.max_iterations}")
        
        # Validate config_version
        if not isinstance(self.config_version, int):
            raise ConfigError(f"config_version must be int, got {type(self.config_version).__name__}")
        if self.config_version != 1:
            raise ConfigError(f"unsupported config_version: {self.config_version} (only 1 is supported)")
        
        # Validate endpoint (after other validations to match test expectations)
        try:
            _parse_endpoint(self.endpoint)
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(f"invalid endpoint: {e}") from e
    
    @property
    def host(self) -> str:
        """Return the host part of the endpoint."""
        return _parse_endpoint(self.endpoint)[0]
    
    @property
    def port(self) -> int:
        """Return the port part of the endpoint."""
        return _parse_endpoint(self.endpoint)[1]


def load_config(path: Path | str) -> FuzzConfig:
    """Load FuzzConfig from a YAML file.
    
    Strict validation: unknown keys raise ConfigError with the key name.
    No silent coercion. UTF-8 BOM is tolerated (utf-8-sig).
    """
    if isinstance(path, str):
        path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise ConfigError(f"cannot read config file {path}: {e}") from e
    
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}") from e
    
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a mapping, got {type(data).__name__}")
    
    # Known keys (must match FuzzConfig fields exactly)
    known_keys = {
        "endpoint", "groups", "iterations", "mutation_classes",
        "seed", "timeout_ms", "concurrency", "capture_cap_bytes",
        "max_iterations", "config_version"
    }
    
    # Check for unknown keys
    for key in data:
        if key not in known_keys:
            raise ConfigError(f"unknown config key: {key!r}")
    
    # Validate and convert
    # endpoint is required
    if "endpoint" not in data:
        raise ConfigError("missing required key: endpoint")
    
    # Convert groups
    if "groups" in data:
        data["groups"] = _parse_groups(data["groups"])
    
    # Convert mutation_classes
    if "mutation_classes" in data:
        data["mutation_classes"] = _parse_mutation_classes(data["mutation_classes"])
    
    # Ensure tuples for immutable fields
    for key in ("groups", "mutation_classes"):
        if key in data and isinstance(data[key], list):
            data[key] = tuple(data[key])
    
    return FuzzConfig(**data)