#!/usr/bin/env python3
"""Check EasyTier's converged core module boundaries without dependencies."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "easytier-core" / "src"
RUST_ROOTS = (
    CORE,
    ROOT / "easytier" / "src",
    ROOT / "easytier-web" / "src",
    ROOT / "easytier-gui" / "src-tauri" / "src",
    ROOT / "easytier-contrib",
)
IGNORED_DIRS = {".git", "node_modules", "target"}

Rule = tuple[str, str, frozenset[str], bool]
PathRef = tuple[tuple[str, ...], int]
Violation = tuple[str, int, str, str]

RULES: tuple[Rule, ...] = (
    (
        "foundation",
        "foundation depends on a domain module",
        frozenset(
            "config packet socket host tunnel listener connectivity peers rpc gateway instance".split()
        ),
        False,
    ),
    (
        "packet",
        "packet depends above the wire-format layer",
        frozenset(
            "socket host tunnel listener connectivity peers rpc gateway instance".split()
        ),
        False,
    ),
    (
        "socket",
        "socket production code depends on a higher layer",
        frozenset(
            "host tunnel listener connectivity peers rpc gateway instance".split()
        ),
        True,
    ),
    (
        "host",
        "host depends above the host seam",
        frozenset("tunnel listener connectivity peers rpc gateway instance".split()),
        False,
    ),
    (
        "config",
        "config reaches into gateway or instance",
        frozenset({"gateway", "instance"}),
        False,
    ),
    (
        "listener",
        "listener reaches into peer, RPC, gateway, or instance domains",
        frozenset({"peers", "rpc", "gateway", "instance"}),
        False,
    ),
    (
        "connectivity",
        "connectivity reaches into gateway or instance",
        frozenset({"gateway", "instance"}),
        False,
    ),
    (
        "peers",
        "peer or RPC code reaches into gateway or instance",
        frozenset({"gateway", "instance"}),
        False,
    ),
    (
        "rpc",
        "peer or RPC code reaches into gateway or instance",
        frozenset({"gateway", "instance"}),
        False,
    ),
    (
        "gateway",
        "gateway reaches into the composition root",
        frozenset({"instance"}),
        False,
    ),
)

OBSOLETE_PATHS = (
    "easytier-core/src/foundation/compressor.rs",
    "easytier-core/src/foundation/compressor",
    "easytier-core/src/gateway/stack.rs",
    "easytier-core/src/gateway/stack",
    "easytier-core/src/gateway/tokio_smoltcp.rs",
    "easytier-core/src/gateway/tokio_smoltcp",
    "easytier-core/src/connectivity/hole_punch/udp/packet.rs",
    "easytier-core/src/connectivity/hole_punch/udp/packet",
    "easytier-core/src/rpc/metrics.rs",
    "easytier-core/src/rpc/metrics",
)
REQUIRED_PATHS = (
    "easytier-core/src/gateway/smoltcp/mod.rs",
    "easytier-core/src/packet/hole_punch.rs",
)

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
USE_RE = re.compile(r"(?<!r#)\buse\b(?P<body>.*?);", re.DOTALL)
TOKEN_RE = re.compile(r"r#[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|::|\S")
PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_#])"
    r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*::\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*)+"
)
MODULE_RE = re.compile(
    r"\b(?:(?P<public>pub)\s*(?P<restriction>\([^)]*\))?\s+)?mod\s+"
    r"(?P<name>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)\b"
)

OBSOLETE_MODULES = {
    "easytier-core/src/foundation/mod.rs": frozenset({"compressor"}),
    "easytier-core/src/gateway/mod.rs": frozenset({"stack", "tokio_smoltcp"}),
    "easytier-core/src/connectivity/hole_punch/udp/mod.rs": frozenset({"packet"}),
    "easytier-core/src/rpc/mod.rs": frozenset({"metrics"}),
}


class ScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class Scan:
    path: Path
    clean: str
    line_starts: tuple[int, ...]
    paths: frozenset[PathRef]


def raw_string_end(source: str, start: int) -> int | None:
    for prefix in ("br", "cr", "r"):
        if not source.startswith(prefix, start):
            continue
        quote = start + len(prefix)
        while quote < len(source) and source[quote] == "#":
            quote += 1
        if quote == len(source) or source[quote] != '"':
            continue
        closing = '"' + source[start + len(prefix) : quote]
        end = source.find(closing, quote + 1)
        if end < 0:
            raise ScanError("unterminated raw string literal")
        return end + len(closing)
    return None


def quoted_end(source: str, quote: int) -> int:
    cursor = quote + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
        elif source[cursor] == '"':
            return cursor + 1
        else:
            cursor += 1
    raise ScanError("unterminated string literal")


def char_literal_end(source: str, quote: int) -> int | None:
    cursor = quote + 1
    if cursor == len(source) or source[cursor] in "\r\n'":
        return None
    if source[cursor] != "\\":
        cursor += 1
    else:
        cursor += 1
        if cursor == len(source) or source[cursor] in "\r\n":
            return None
        if source[cursor] == "x":
            cursor += 3
        elif source[cursor] == "u" and source.startswith("{", cursor + 1):
            closing = source.find("}", cursor + 2)
            if closing < 0:
                return None
            cursor = closing + 1
        else:
            cursor += 1
    return cursor + 1 if cursor < len(source) and source[cursor] == "'" else None


def mask_non_code(source: str) -> str:
    """Replace comments and literals with spaces while preserving offsets."""
    masked = list(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] != "\n":
                masked[index] = " "

    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            end = len(source) if end < 0 else end
            blank(cursor, end)
            cursor = end
            continue

        if source.startswith("/*", cursor):
            start = cursor
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise ScanError("unterminated block comment")
            blank(start, cursor)
            continue

        end = raw_string_end(source, cursor)
        if end is not None:
            blank(cursor, end)
            cursor = end
            continue

        quote = cursor + 1 if source.startswith(('b"', 'c"'), cursor) else cursor
        if source[quote] == '"':
            end = quoted_end(source, quote)
            blank(cursor, end)
            cursor = end
            continue

        quote = cursor + 1 if source.startswith("b'", cursor) else cursor
        if source[quote] == "'":
            end = char_literal_end(source, quote)
            if end is not None:
                blank(cursor, end)
                cursor = end
                continue
        cursor += 1

    return "".join(masked)


def make_line_starts(source: str) -> tuple[int, ...]:
    return (0, *(match.end() for match in re.finditer("\n", source)))


def line_number(starts: tuple[int, ...], offset: int) -> int:
    return bisect_right(starts, offset)


def is_name(value: str) -> bool:
    return NAME_RE.fullmatch(value) is not None


class UseParser:
    def __init__(self, tokens: list[tuple[str, int]]):
        self.tokens = tokens
        self.cursor = 0

    def accept(self, value: str) -> tuple[str, int] | None:
        if self.cursor < len(self.tokens) and self.tokens[self.cursor][0] == value:
            token = self.tokens[self.cursor]
            self.cursor += 1
            return token
        return None

    def name(self) -> tuple[str, int]:
        if self.cursor == len(self.tokens) or not is_name(self.tokens[self.cursor][0]):
            found = "end of statement"
            if self.cursor < len(self.tokens):
                found = repr(self.tokens[self.cursor][0])
            raise ScanError(f"expected a name in use tree, found {found}")
        token = self.tokens[self.cursor]
        self.cursor += 1
        return token

    def tree(self, prefix: tuple[str, ...] = ()) -> list[PathRef]:
        self.accept("::")
        if self.accept("{"):
            paths: list[PathRef] = []
            while not self.accept("}"):
                paths.extend(self.tree(prefix))
                if self.accept(","):
                    continue
                if self.accept("}"):
                    break
                raise ScanError("expected ',' or '}' in use tree")
            return paths
        if star := self.accept("*"):
            return [(prefix + ("*",), star[1])]

        name, line = self.name()
        path = prefix if name == "self" and prefix else prefix + (name,)
        if self.accept("as"):
            self.name()
            return [(path, line)]
        if self.accept("::"):
            return self.tree(path)
        return [(path, line)]

    def parse(self) -> list[PathRef]:
        paths = self.tree()
        if self.cursor != len(self.tokens):
            raise ScanError(f"unexpected {self.tokens[self.cursor][0]!r} in use tree")
        return paths


def use_paths(clean: str, starts: tuple[int, ...]) -> set[PathRef]:
    paths: set[PathRef] = set()
    for statement in USE_RE.finditer(clean):
        body = statement.group("body")
        body_start = statement.start("body")
        tokens = []
        for match in TOKEN_RE.finditer(body):
            value = match.group()
            if value.startswith("r#"):
                value = value[2:]
            tokens.append((value, line_number(starts, body_start + match.start())))
        if not tokens or (not is_name(tokens[0][0]) and tokens[0][0] not in {"::", "{"}):
            continue
        try:
            paths.update(UseParser(tokens).parse())
        except ScanError:
            if "$" in body or "[<" in body:
                continue
            raise
    return paths


def qualified_paths(clean: str, starts: tuple[int, ...]) -> set[PathRef]:
    paths: set[PathRef] = set()
    outside_uses = list(clean)
    for statement in USE_RE.finditer(clean):
        body = statement.group("body")
        if "$" in body or "[<" in body:
            continue
        for index in range(statement.start(), statement.end()):
            if outside_uses[index] != "\n":
                outside_uses[index] = " "
    for match in PATH_RE.finditer("".join(outside_uses)):
        parts = tuple(
            part.removeprefix("r#")
            for part in re.split(r"\s*::\s*", match.group())
        )
        paths.add((parts, line_number(starts, match.start())))
    return paths


def scan_file(path: Path) -> Scan:
    try:
        clean = mask_non_code(path.read_text(encoding="utf-8"))
        starts = make_line_starts(clean)
        paths = use_paths(clean, starts) | qualified_paths(clean, starts)
        return Scan(path, clean, starts, frozenset(paths))
    except (OSError, UnicodeError, ScanError) as error:
        raise ScanError(f"{path.relative_to(ROOT)}: {error}") from error


def rust_files(root: Path) -> set[Path]:
    if not root.exists():
        return set()
    return {
        path
        for path in root.rglob("*.rs")
        if not any(part in IGNORED_DIRS for part in path.parts)
    }


def module_path(path: Path) -> tuple[str, ...]:
    relative = path.relative_to(CORE)
    if relative.name == "lib.rs":
        return ()
    if relative.name == "mod.rs":
        return relative.parent.parts
    return relative.with_suffix("").parts


def resolve(parts: tuple[str, ...], current: tuple[str, ...]) -> tuple[str, ...]:
    if parts[0] == "crate":
        return tuple(part for part in parts[1:] if part != "*")
    if parts[0] == "self":
        return current + tuple(part for part in parts[1:] if part != "*")
    if parts[0] == "super":
        supers = 0
        while supers < len(parts) and parts[supers] == "super":
            supers += 1
        return current[: max(0, len(current) - supers)] + tuple(
            part for part in parts[supers:] if part != "*"
        )
    return current + tuple(part for part in parts if part != "*")


def contains(parts: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    width = len(expected)
    return any(
        parts[index : index + width] == expected
        for index in range(len(parts) - width + 1)
    )


def legacy_reason(parts: tuple[str, ...]) -> str | None:
    exact = (
        ("listener", "SocketListener"),
        ("rpc", "metrics"),
        ("foundation", "compressor"),
        ("gateway", "config"),
        ("gateway", "proxy", "ProxyRuntimeConfig"),
        ("gateway", "stack"),
        ("gateway", "tokio_smoltcp"),
        ("socket", "host"),
    )
    for expected in exact:
        if contains(parts, expected):
            return "::".join(expected)
    for limiter in ("ByteLimiter", "ArcByteLimiter"):
        expected = ("peers", "context", limiter)
        if contains(parts, expected):
            return "::".join(expected)
    for symbol in ("GatewayRuntimeConfig", "PortForwardConfig"):
        for index in range(len(parts) - 1):
            if parts[index : index + 2] == ("gateway", symbol) and (
                index == 0 or parts[index - 1] != "config"
            ):
                return f"gateway::{symbol}"
    for symbol in (
        "HOLE_PUNCH_PACKET_BODY_LEN",
        "hole_punch_packet_tid",
        "new_hole_punch_packet",
    ):
        expected = ("connectivity", "hole_punch", "udp", symbol)
        if contains(parts, expected):
            return "::".join(expected)
    return None


def module_declarations(scan: Scan) -> list[tuple[str, int, bool, bool]]:
    return [
        (
            match.group("name").removeprefix("r#"),
            line_number(scan.line_starts, match.start()),
            match.group("public") is not None,
            match.group("restriction") is not None,
        )
        for match in MODULE_RE.finditer(scan.clean)
    ]


def public_modules(scan: Scan) -> list[tuple[str, int, bool]]:
    return [
        (name, line, restricted)
        for name, line, public, restricted in module_declarations(scan)
        if public
    ]


def check_layout(scans: dict[Path, Scan]) -> set[Violation]:
    violations = {
        (path, 1, "obsolete path still exists", path)
        for path in OBSOLETE_PATHS
        if (ROOT / path).exists()
    }
    violations.update(
        (path, 1, "required path is missing", path)
        for path in REQUIRED_PATHS
        if not (ROOT / path).is_file()
    )
    for relative, forbidden in OBSOLETE_MODULES.items():
        for name, line, _public, _restricted in module_declarations(
            scans[ROOT / relative]
        ):
            if name in forbidden:
                violations.add(
                    (relative, line, "obsolete module declaration", name)
                )
    return violations


def check_visibility(scans: dict[Path, Scan]) -> set[Violation]:
    violations: set[Violation] = set()
    gateway = CORE / "gateway" / "mod.rs"
    for name, line, _restricted in public_modules(scans[gateway]):
        if name in {"module", "smoltcp", "socks5"}:
            violations.add(
                (
                    str(gateway.relative_to(ROOT)),
                    line,
                    "gateway implementation module is externally visible",
                    name,
                )
            )
    hole_punch = CORE / "connectivity" / "hole_punch" / "mod.rs"
    for name, line, restricted in public_modules(scans[hole_punch]):
        if name in {"tcp", "udp"} and not restricted:
            violations.add(
                (
                    str(hole_punch.relative_to(ROOT)),
                    line,
                    "hole-punch engine module is externally visible",
                    name,
                )
            )
    return violations


def check_legacy(scans: tuple[Scan, ...]) -> set[Violation]:
    violations: set[Violation] = set()
    for scan in scans:
        relative = str(scan.path.relative_to(ROOT))
        current = module_path(scan.path) if CORE in scan.path.parents else None
        for match in re.finditer(r"\brpc_impl\b", scan.clean):
            violations.add(
                (
                    relative,
                    line_number(scan.line_starts, match.start()),
                    "legacy core module path",
                    "rpc_impl",
                )
            )
        for parts, line in scan.paths:
            if current is not None and parts[0] in {"crate", "self", "super"}:
                reason = legacy_reason(resolve(parts, current))
            else:
                reason = legacy_reason(parts)
            if reason is not None:
                violations.add((relative, line, "legacy core module path", reason))
    return violations


def check_boundaries(core_scans: tuple[Scan, ...]) -> set[Violation]:
    violations: set[Violation] = set()
    for scan in core_scans:
        relative_to_core = scan.path.relative_to(CORE)
        if not relative_to_core.parts:
            continue
        directory = relative_to_core.parts[0]
        current = module_path(scan.path)
        relative = str(scan.path.relative_to(ROOT))
        for rule_directory, label, forbidden, exclude_tests in RULES:
            if directory != rule_directory or (exclude_tests and scan.path.name == "tests.rs"):
                continue
            for parts, line in scan.paths:
                resolved = resolve(parts, current)
                if resolved and resolved[0] in forbidden:
                    violations.add((relative, line, label, "::".join(parts)))
    return violations


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScanError(f"self-test failed: {message}")


def self_test() -> None:
    imports = """
use crate::{packet::ZCPacket, connectivity::stun::StunInfoProvider};
use crate::connectivity;
use crate::connectivity as conn;
pub(crate) use crate::{connectivity::Thing, packet::ZCPacket};
use crate::gateway::{GatewayRuntimeConfig, PortForwardConfig};
use crate::connectivity::hole_punch::udp::{
    new_hole_punch_packet,
    hole_punch_packet_tid as packet_tid,
};
"""
    clean = mask_non_code(imports)
    parsed = {parts for parts, _line in use_paths(clean, make_line_starts(clean))}
    expected = {
        ("crate", "packet", "ZCPacket"),
        ("crate", "connectivity", "stun", "StunInfoProvider"),
        ("crate", "connectivity"),
        ("crate", "connectivity", "Thing"),
        ("crate", "gateway", "GatewayRuntimeConfig"),
        ("crate", "gateway", "PortForwardConfig"),
        ("crate", "connectivity", "hole_punch", "udp", "new_hole_punch_packet"),
        ("crate", "connectivity", "hole_punch", "udp", "hole_punch_packet_tid"),
    }
    require(expected <= parsed, "a supported use form was lost")
    resolved = {resolve(parts, ("socket", "example")) for parts in parsed}
    require(
        ("connectivity",) in resolved
        and ("connectivity", "stun", "StunInfoProvider") in resolved,
        "a crate dependency was not resolved",
    )
    require(
        legacy_reason(("crate", "gateway", "GatewayRuntimeConfig"))
        == "gateway::GatewayRuntimeConfig",
        "a grouped gateway legacy path was missed",
    )
    require(
        legacy_reason(
            ("crate", "connectivity", "hole_punch", "udp", "new_hole_punch_packet")
        )
        == "connectivity::hole_punch::udp::new_hole_punch_packet",
        "a grouped hole-punch legacy path was missed",
    )

    visibility = """
pub mod module;
pub(crate) mod r#smoltcp;
pub(super) mod socks5;
pub(in crate) mod hidden;
pub mod r#udp;
mod r#stack;
mod private;
"""
    clean = mask_non_code(visibility)
    fake_scan = Scan(Path("test.rs"), clean, make_line_starts(clean), frozenset())
    require(
        {(name, restricted) for name, _line, restricted in public_modules(fake_scan)}
        == {
            ("module", False),
            ("smoltcp", True),
            ("socks5", True),
            ("hidden", True),
            ("udp", False),
        },
        "a restricted module visibility was missed",
    )
    require(
        "stack"
        in {
            name
            for name, _line, _public, _restricted in module_declarations(fake_scan)
        },
        "a raw private module declaration was missed",
    )
    require(
        legacy_reason(resolve(("self", "stack"), ("gateway",)))
        == "gateway::stack"
        and legacy_reason(
            resolve(("super", "super", "stack"), ("gateway", "proxy", "adapter"))
        )
        == "gateway::stack",
        "a self or super legacy path was missed",
    )
    legacy_scans = (
        Scan(
            CORE / "gateway" / "mod.rs",
            "",
            (0,),
            frozenset({(("self", "stack", "SmolTcpStack"), 1)}),
        ),
        Scan(
            CORE / "gateway" / "proxy" / "adapter.rs",
            "",
            (0,),
            frozenset({(("super", "super", "stack", "SmolTcpStack"), 1)}),
        ),
    )
    require(
        len(check_legacy(legacy_scans)) == 2,
        "the legacy gate did not reject self and super paths",
    )
    macro_imports = """
use $crate::gateway::Thing;
use crate::gateway::[<GeneratedThing>];
"""
    clean = mask_non_code(macro_imports)
    starts = make_line_starts(clean)
    fallback = qualified_paths(clean, starts)
    require(
        len(
            {
                parts
                for parts, _line in fallback
                if resolve(parts, ("foundation",))[0] == "gateway"
            }
        )
        == 2,
        "macro-generated use paths were hidden from the fallback scanner",
    )
    ignored = '// use crate::connectivity;\nlet x = "crate::gateway::stack";\n'
    clean = mask_non_code(ignored)
    starts = make_line_starts(clean)
    require(
        not use_paths(clean, starts) and not qualified_paths(clean, starts),
        "a comment or string was parsed as code",
    )


def main() -> int:
    self_test()
    if len(sys.argv) > 1:
        if sys.argv[1:] == ["--self-test"]:
            print("core module boundary scanner self-test: ok")
            return 0
        print(f"usage: {Path(sys.argv[0]).name} [--self-test]", file=sys.stderr)
        return 2

    files = {path for root in RUST_ROOTS for path in rust_files(root)}
    scans = tuple(scan_file(path) for path in sorted(files))
    by_path = {scan.path: scan for scan in scans}
    core_scans = tuple(scan for scan in scans if CORE in scan.path.parents)

    violations = check_layout(by_path)
    violations.update(check_visibility(by_path))
    violations.update(check_legacy(scans))
    violations.update(check_boundaries(core_scans))
    if violations:
        for path, line, label, detail in sorted(violations):
            print(
                f"{path}:{line}: module boundary violation: {label}: {detail}",
                file=sys.stderr,
            )
        return 1
    print("core module boundaries: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScanError as error:
        print(f"module boundary check failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
