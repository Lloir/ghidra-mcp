"""Service configuration loading and boundary validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from socket import inet_aton
from typing import Mapping
import os
import tomllib
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """The config file or environment variables violate the public contract."""


def validate_http_auth_token(token: str | None) -> None:
    if token is None or not token.strip():
        raise ConfigurationError("streamable-http requires GHIDRA_MCP_AUTH_TOKEN to be set")
    if token != token.strip():
        raise ConfigurationError(
            "GHIDRA_MCP_AUTH_TOKEN must not contain leading or trailing whitespace"
        )
    if len(token.encode("utf-8")) < 32:
        raise ConfigurationError("GHIDRA_MCP_AUTH_TOKEN requires at least 32 UTF-8 bytes")


@dataclass(frozen=True, slots=True)
class Settings:
    install_dir: Path | None = None
    analysis_timeout_seconds: int = 300
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8765
    storage_root: Path = Path("data/projects")
    input_root: Path | None = None
    public_url: str | None = None
    auth_token: str | None = field(default=None, repr=False)


_ALLOWED_KEYS = {
    "ghidra": {"install_dir", "analysis_timeout_seconds"},
    "server": {"transport", "host", "port", "public_url"},
    "storage": {"root", "input_root"},
}


def _read_toml(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {}
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    for section, values in document.items():
        if section not in _ALLOWED_KEYS:
            raise ConfigurationError(f"Unknown config section {section}, from {path.name}")
        if not isinstance(values, dict):
            raise ConfigurationError(f"Config section {section} must be a table, from {path.name}")
        for key in values:
            if key not in _ALLOWED_KEYS[section]:
                raise ConfigurationError(
                    f"Unknown config key {section}.{key}, from {path.name}"
                )
    return document


def _read_dotenv(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not key.strip():
            raise ConfigurationError(f"Invalid .env line {line_number}, from {path.name}")
        key = key.strip()
        if (
            key == "GHIDRA_MCP_AUTH_TOKEN"
            and len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {'"', "'"}
        ):
            value = value[1:-1]
        elif key != "GHIDRA_MCP_AUTH_TOKEN":
            value = value.strip().strip('"').strip("'")
        values[key] = value
    return values


def _integer(value: object, *, key: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{key} must be an integer, got {value!r}") from error


def normalize_http_public_url(value: str | None) -> str:
    if value is None or not value.strip():
        raise ConfigurationError("streamable-http requires GHIDRA_MCP_PUBLIC_URL to be set")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "GHIDRA_MCP_PUBLIC_URL must be a valid HTTP(S) root URL"
        ) from error
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or _is_unspecified_host(hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in parsed.netloc)
    ):
        raise ConfigurationError("GHIDRA_MCP_PUBLIC_URL must be a valid HTTP(S) root URL")
    normalized = f"{parsed.scheme}://{parsed.hostname}"
    if ":" in parsed.hostname:
        normalized = f"{parsed.scheme}://[{parsed.hostname}]"
    if port is not None:
        normalized = f"{normalized}:{port}"
    return normalized


def _is_unspecified_host(hostname: str) -> bool:
    candidate = hostname.removesuffix(".")
    try:
        address = ip_address(candidate)
        mapped_address = getattr(address, "ipv4_mapped", None)
        return address.is_unspecified or (
            mapped_address is not None and mapped_address.is_unspecified
        )
    except ValueError:
        try:
            return inet_aton(candidate) == b"\0\0\0\0"
        except OSError:
            return False


def load_settings(
    *,
    config_path: Path | None = Path("data/config/default.toml"),
    dotenv_path: Path | None = Path(".env"),
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Merge configuration in this order: environment variables, .env, TOML, defaults."""

    document = _read_toml(config_path)
    dotenv = _read_dotenv(dotenv_path)
    environment = os.environ if environ is None else environ

    server = document.get("server", {})
    ghidra = document.get("ghidra", {})
    storage = document.get("storage", {})
    assert isinstance(server, dict) and isinstance(ghidra, dict) and isinstance(storage, dict)

    def value(
        env_key: str, toml_values: dict[str, object], toml_key: str, default: object
    ) -> object:
        return environment.get(env_key, dotenv.get(env_key, toml_values.get(toml_key, default)))

    transport = str(value("GHIDRA_MCP_TRANSPORT", server, "transport", "stdio"))
    if transport not in {"stdio", "streamable-http"}:
        raise ConfigurationError("server.transport must be stdio or streamable-http")
    auth_token = environment.get("GHIDRA_MCP_AUTH_TOKEN", dotenv.get("GHIDRA_MCP_AUTH_TOKEN", ""))
    auth_token = auth_token or None
    if transport == "streamable-http":
        validate_http_auth_token(auth_token)
    input_value = value("GHIDRA_MCP_INPUT_ROOT", storage, "input_root", "")
    input_root = Path(str(input_value)).resolve() if input_value else None
    if transport == "streamable-http" and input_root is None:
        raise ConfigurationError("streamable-http requires GHIDRA_MCP_INPUT_ROOT to be set")
    install_value = value("GHIDRA_INSTALL_DIR", ghidra, "install_dir", "")
    install_dir = Path(str(install_value)).resolve() if install_value else None
    analysis_timeout_seconds = _integer(
        value(
            "GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS",
            ghidra,
            "analysis_timeout_seconds",
            300,
        ),
        key="ghidra.analysis_timeout_seconds",
    )
    if not 1 <= analysis_timeout_seconds <= 3600:
        raise ConfigurationError("ghidra.analysis_timeout_seconds must be between 1 and 3600")
    port = _integer(value("GHIDRA_MCP_PORT", server, "port", 8765), key="server.port")
    if not 1 <= port <= 65535:
        raise ConfigurationError("server.port must be between 1 and 65535")
    public_url_value = str(value("GHIDRA_MCP_PUBLIC_URL", server, "public_url", "")).strip()
    public_url = (
        normalize_http_public_url(public_url_value) if transport == "streamable-http" else None
    )

    return Settings(
        install_dir=install_dir,
        analysis_timeout_seconds=analysis_timeout_seconds,
        transport=transport,
        host=str(value("GHIDRA_MCP_HOST", server, "host", "127.0.0.1")),
        port=port,
        storage_root=Path(str(value("GHIDRA_MCP_STORAGE_ROOT", storage, "root", "data/projects"))),
        input_root=input_root,
        public_url=public_url,
        auth_token=auth_token,
    )
