"""Deterministic, observation-only AST import-boundary checks.

This module deliberately does not admit work or mutate company state.  It
turns a supplied, immutable Git-blob view into stable findings which a later
admission gate may consume.  Boundary checks visit every literal AOI-internal
import, including imports nested in functions.  Import-time cycle checks use
only module-executed, literal imports.  They traverse control-flow and class
bodies (class body included; function/method bodies excluded), but stop at
functions, async functions, and lambdas, so a deliberate lazy import is not
mistaken for an import-time cycle.  Dynamic ``importlib`` and ``__import__``
calls are intentionally outside literal-import coverage.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import unicodedata

from .file_governance import (
    FileGovernanceError,
    GitBlob,
    GovernanceFinding,
    ImportBoundaryRuleV1,
    normalize_repo_path,
)

_AOI_ROOT = "aoi_orgware"


@dataclass(frozen=True, slots=True)
class _ModuleSource:
    """One exact Python module recovered from a tracked ``src/`` blob."""

    module: str
    path: str
    is_package: bool
    tree: ast.Module


DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES = (
    ImportBoundaryRuleV1(
        1,
        "company-dogfood-v1",
        "aoi_orgware.company",
        (
            "aoi_orgware.company",
            "aoi_orgware.frozen_json",
            "aoi_orgware.semantic_events",
        ),
        True,
    ),
)


def evaluate_import_governance(
    files: Mapping[str, GitBlob],
    rules: Sequence[ImportBoundaryRuleV1] = DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES,
) -> tuple[GovernanceFinding, ...]:
    """Return canonical boundary and import-time cycle findings.

    ``files`` is an in-memory Git tree, normally the exact source snapshot
    used by file governance.  Only Python blobs below ``src/`` participate.
    Every participating blob must be strict UTF-8 and syntactically valid.
    Rules must have unique identifiers, non-overlapping source coverage, and
    at least one matching source module.  Stdlib and third-party imports are
    intentionally outside this AOI-internal contract.  Boundary checks include
    all literal imports.  Cycle checks conservatively traverse both body and
    else of every conditional, including direct, qualified, negated, aliased,
    and compound ``TYPE_CHECKING`` forms.  This intentionally over-approximates
    dependencies; it does not claim flow-sensitive runtime proof.
    """

    sources = _source_modules(files)
    checked_rules = _validate_rules(rules, sources)
    modules = {item.module: item for item in sources}
    graph = _module_scope_graph(sources, modules)
    findings: list[GovernanceFinding] = []
    for rule in checked_rules:
        findings.extend(_boundary_findings(rule, sources, modules))
        if rule.forbid_cycles:
            findings.extend(_cycle_findings(rule, graph, modules))
    return tuple(sorted(set(findings)))


def _source_modules(files: Mapping[str, GitBlob]) -> tuple[_ModuleSource, ...]:
    if not isinstance(files, Mapping):
        raise FileGovernanceError("import-governance files must be a mapping")
    if any(not isinstance(raw_path, str) for raw_path in files):
        raise FileGovernanceError("import-governance path must be text")
    records: list[_ModuleSource] = []
    identities: set[str] = set()
    folded_identities: set[str] = set()
    for raw_path in _ordinal(files):
        if not isinstance(raw_path, str):
            raise FileGovernanceError("import-governance path must be text")
        path = normalize_repo_path(raw_path)
        blob = files[raw_path]
        if not isinstance(blob, GitBlob):
            raise FileGovernanceError("import-governance entry must be a Git blob")
        if not path.startswith("src/") or not path.endswith(".py"):
            continue
        module, is_package = _module_identity(path)
        if module in identities:
            raise FileGovernanceError("duplicate Python module identity")
        if module.casefold() in folded_identities:
            raise FileGovernanceError("case-folding Python module identity collision")
        identities.add(module)
        folded_identities.add(module.casefold())
        try:
            text = blob.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileGovernanceError(f"{path} is not strict UTF-8") from exc
        try:
            tree = ast.parse(text, filename=path, mode="exec")
        except (SyntaxError, ValueError) as exc:
            raise FileGovernanceError(f"{path} is not valid Python source") from exc
        records.append(_ModuleSource(module, path, is_package, tree))
    _reject_module_file_prefixes(records)
    return tuple(records)


def _reject_module_file_prefixes(records: Sequence[_ModuleSource]) -> None:
    """Reject a module file which would shadow a tracked child module tree."""

    for parent in records:
        if parent.is_package:
            continue
        folded_parent = parent.module.casefold() + "."
        if any(
            child is not parent and child.module.casefold().startswith(folded_parent)
            for child in records
        ):
            raise FileGovernanceError("module file shadows a Python package prefix")


def _module_identity(path: str) -> tuple[str, bool]:
    parts = path.split("/")[1:]
    filename = parts.pop()
    stem = filename[:-3]
    is_package = stem == "__init__"
    if is_package:
        if not parts:
            raise FileGovernanceError("src/__init__.py has no module identity")
    else:
        parts.append(stem)
    if not parts or any(not part.isidentifier() for part in parts):
        raise FileGovernanceError("Python source path has no exact module identity")
    module = ".".join(parts)
    if unicodedata.normalize("NFC", module) != module:
        raise FileGovernanceError("Python module identity must already be NFC")
    return module, is_package


def _validate_rules(
    rules: Sequence[ImportBoundaryRuleV1],
    sources: Sequence[_ModuleSource],
) -> tuple[ImportBoundaryRuleV1, ...]:
    if not isinstance(rules, Sequence) or isinstance(rules, (bytes, str)):
        raise FileGovernanceError("import-boundary rules must be a sequence")
    checked = tuple(rules)
    ids: set[str] = set()
    for rule in checked:
        if not isinstance(rule, ImportBoundaryRuleV1):
            raise FileGovernanceError("invalid import-boundary rule")
        if rule.rule_id in ids:
            raise FileGovernanceError("duplicate import-boundary rule id")
        ids.add(rule.rule_id)
        if not any(_covers(rule.source_prefix, item.module) for item in sources):
            raise FileGovernanceError("import-boundary rule has no matching source")
    for index, first in enumerate(checked):
        for second in checked[index + 1:]:
            if _covers(first.source_prefix, second.source_prefix) or _covers(
                second.source_prefix, first.source_prefix
            ):
                raise FileGovernanceError("overlapping import-boundary source prefixes")
    return checked


def _boundary_findings(
    rule: ImportBoundaryRuleV1,
    sources: Sequence[_ModuleSource],
    modules: Mapping[str, _ModuleSource],
) -> list[GovernanceFinding]:
    findings: list[GovernanceFinding] = []
    for source in sources:
        if not _covers(rule.source_prefix, source.module):
            continue
        for node in ast.walk(source.tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for target in _boundary_targets(node, source, modules):
                if _is_aoi_internal(target) and not any(
                    _covers(allowed, target)
                    for allowed in rule.allowed_import_prefixes
                ):
                    findings.append(_finding(
                        f"import_boundary:{rule.rule_id}", source.path,
                        source.module, target, getattr(node, "lineno", 0),
                    ))
    return findings


def _module_scope_graph(
    sources: Sequence[_ModuleSource],
    modules: Mapping[str, _ModuleSource],
) -> Mapping[str, tuple[str, ...]]:
    graph: dict[str, tuple[str, ...]] = {}
    for source in sources:
        targets: set[str] = set()
        for node in _module_executed_imports(source.tree):
            targets.update(_cycle_targets(node, source, modules))
        graph[source.module] = tuple(_ordinal(targets))
    return graph


def _module_executed_imports(
    tree: ast.Module,
) -> Iterable[ast.Import | ast.ImportFrom]:
    """Yield literal imports executed while a module is imported.

    Control-flow statement blocks are explored iteratively.  Every conditional
    contributes both body and else, including every ``TYPE_CHECKING`` spelling:
    that conservative over-approximation is fail-closed against rebinding and
    intentionally does not attempt flow-sensitive runtime evaluation.
    """

    pending: list[ast.stmt] = list(reversed(tree.body))
    while pending:
        statement = pending.pop()
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            yield statement
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        elif isinstance(statement, ast.ClassDef):
            _push_statements(pending, statement.body)
        elif isinstance(statement, ast.If):
            _push_statements(pending, statement.orelse)
            _push_statements(pending, statement.body)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            _push_statements(pending, statement.orelse)
            _push_statements(pending, statement.body)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            _push_statements(pending, statement.body)
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            _push_statements(pending, statement.finalbody)
            _push_statements(pending, statement.orelse)
            for handler in reversed(statement.handlers):
                _push_statements(pending, handler.body)
            _push_statements(pending, statement.body)
        elif isinstance(statement, ast.Match):
            for case in reversed(statement.cases):
                _push_statements(pending, case.body)


def _push_statements(pending: list[ast.stmt], statements: Sequence[ast.stmt]) -> None:
    pending.extend(reversed(statements))


def _cycle_findings(
    rule: ImportBoundaryRuleV1,
    graph: Mapping[str, tuple[str, ...]],
    modules: Mapping[str, _ModuleSource],
) -> list[GovernanceFinding]:
    findings: list[GovernanceFinding] = []
    for component in _strongly_connected_components(graph):
        if not any(_covers(rule.source_prefix, module) for module in component):
            continue
        if len(component) == 1 and component[0] not in graph[component[0]]:
            continue
        paths = _ordinal(modules[module].path for module in component)
        findings.append(_finding(
            f"import_cycle:{rule.rule_id}", paths[0], *component,
        ))
    return findings


def _boundary_targets(
    node: ast.Import | ast.ImportFrom,
    source: _ModuleSource,
    modules: Mapping[str, _ModuleSource],
) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        literal_targets = tuple(alias.name for alias in node.names)
    else:
        base = _from_base(node, source)
        if base is None:
            return ()
        literal_targets = (() if node.module is None else (base,)) + tuple(
            f"{base}.{alias.name}"
            for alias in node.names
            if f"{base}.{alias.name}" in modules
        )
    return _executed_import_targets(
        literal_targets, source, modules, include_unmapped_direct=True,
    )


def _cycle_targets(
    node: ast.Import | ast.ImportFrom,
    source: _ModuleSource,
    modules: Mapping[str, _ModuleSource],
) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        literal_targets = tuple(alias.name for alias in node.names)
    else:
        base = _from_base(node, source)
        if base is None:
            return ()
        literal_targets = (() if node.module is None else (base,)) + tuple(
            f"{base}.{alias.name}"
            for alias in node.names
            if f"{base}.{alias.name}" in modules
        )
    return _executed_import_targets(
        literal_targets, source, modules, include_unmapped_direct=False,
    )


def _executed_import_targets(
    literal_targets: Sequence[str],
    source: _ModuleSource,
    modules: Mapping[str, _ModuleSource],
    *, include_unmapped_direct: bool,
) -> tuple[str, ...]:
    """Add exact modules plus package initializers actually executed by import."""

    initialized_packages = _source_initialized_packages(source, modules)
    targets: set[str] = set()
    for target in literal_targets:
        entry = modules.get(target)
        if entry is None:
            if include_unmapped_direct:
                targets.add(target)
        elif not (entry.is_package and target in initialized_packages):
            targets.add(target)
        for prefix in _package_prefixes(target):
            package = modules.get(prefix)
            if (
                package is not None
                and package.is_package
                and prefix not in initialized_packages
            ):
                targets.add(prefix)
    return tuple(_ordinal(targets))


def _source_initialized_packages(
    source: _ModuleSource,
    modules: Mapping[str, _ModuleSource],
) -> frozenset[str]:
    """Return package modules already initialized before this source executes."""

    parts = source.module.split(".")
    limit = len(parts) if source.is_package else len(parts) - 1
    return frozenset(
        prefix
        for index in range(1, limit + 1)
        if (prefix := ".".join(parts[:index])) in modules
        and modules[prefix].is_package
    )


def _package_prefixes(module: str) -> tuple[str, ...]:
    parts = module.split(".")
    return tuple(".".join(parts[:index]) for index in range(1, len(parts) + 1))


def _from_base(node: ast.ImportFrom, source: _ModuleSource) -> str | None:
    if node.level == 0:
        return node.module
    package_parts = source.module.split(".")
    if not source.is_package:
        package_parts.pop()
    drop = node.level - 1
    if node.level > len(package_parts):
        raise FileGovernanceError("relative import resolves outside its package")
    base = package_parts[:len(package_parts) - drop]
    if node.module:
        base.extend(node.module.split("."))
    return ".".join(base) or None


def _strongly_connected_components(
    graph: Mapping[str, tuple[str, ...]],
) -> tuple[tuple[str, ...], ...]:
    """Bounded iterative Kosaraju SCCs with ordinal, platform-stable output."""

    seen: set[str] = set()
    finish: list[str] = []
    for root in _ordinal(graph):
        if root in seen:
            continue
        pending: list[tuple[str, bool]] = [(root, False)]
        while pending:
            module, expanded = pending.pop()
            if expanded:
                finish.append(module)
                continue
            if module in seen:
                continue
            seen.add(module)
            pending.append((module, True))
            for target in reversed(graph[module]):
                if target not in seen:
                    pending.append((target, False))
    reverse: dict[str, list[str]] = {module: [] for module in graph}
    for module, targets in graph.items():
        for target in targets:
            reverse[target].append(module)
    result: list[tuple[str, ...]] = []
    assigned: set[str] = set()
    for root in reversed(finish):
        if root in assigned:
            continue
        component: list[str] = []
        reverse_pending: list[str] = [root]
        assigned.add(root)
        while reverse_pending:
            module = reverse_pending.pop()
            component.append(module)
            for target in reversed(_ordinal(reverse[module])):
                if target not in assigned:
                    assigned.add(target)
                    reverse_pending.append(target)
        result.append(tuple(_ordinal(component)))
    return tuple(sorted(result, key=lambda component: tuple(item.encode("utf-8") for item in component)))


def _covers(prefix: str, module: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _is_aoi_internal(module: str) -> bool:
    return _covers(_AOI_ROOT, module)


def _finding(rule_id: str, path: str, *evidence: object) -> GovernanceFinding:
    canonical = "\n".join((rule_id, path, *(str(item) for item in evidence))).encode("utf-8")
    return GovernanceFinding("error", rule_id, path, sha256(canonical).hexdigest())


def _ordinal(values: Iterable[str]) -> list[str]:
    return sorted(values, key=lambda value: value.encode("utf-8"))


__all__ = [
    "DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES",
    "evaluate_import_governance",
]
