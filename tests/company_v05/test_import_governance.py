"""AOI-SYNTHETIC-FIXTURE-V1 tests for pure AST import governance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import pytest

from aoi_orgware.company.file_governance import (
    FileGovernanceError,
    GitBlob,
    ImportBoundaryRuleV1,
)
from aoi_orgware.company.import_governance import (
    DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES,
    evaluate_import_governance,
)


def _files(**modules: str | bytes) -> dict[str, GitBlob]:
    result: dict[str, GitBlob] = {}
    for module, source in modules.items():
        suffix = "/__init__.py" if module.endswith(".__init__") else ".py"
        module_path = module.removesuffix(".__init__").replace(".", "/")
        raw = source if isinstance(source, bytes) else source.encode("utf-8")
        result[f"src/{module_path}{suffix}"] = GitBlob("100644", raw)
    return result


def _rule(
    *, source: str = "aoi_orgware.company",
    allowed: tuple[str, ...] = ("aoi_orgware.company",),
    cycles: bool = True,
    rule_id: str = "company-v1",
) -> ImportBoundaryRuleV1:
    return ImportBoundaryRuleV1(1, rule_id, source, allowed, cycles)


def test_default_company_dogfood_rule_is_frozen() -> None:
    assert DEFAULT_COMPANY_IMPORT_BOUNDARY_RULES == (
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


def test_default_rule_allows_only_the_named_low_level_json_dependencies() -> None:
    files = _files(
        **{
            "aoi_orgware.company.worker": (
                "import aoi_orgware.frozen_json\n"
                "import aoi_orgware.semantic_events\n"
                "import aoi_orgware.unrelated\n"
            ),
            "aoi_orgware.frozen_json": "VALUE = 1\n",
            "aoi_orgware.semantic_events": "VALUE = 2\n",
            "aoi_orgware.unrelated": "VALUE = 3\n",
        }
    )
    findings = evaluate_import_governance(files)
    assert [(item.rule_id, item.path) for item in findings] == [
        (
            "import_boundary:company-dogfood-v1",
            "src/aoi_orgware/company/worker.py",
        ),
    ]


def test_function_local_aoi_import_is_a_boundary_violation() -> None:
    files = _files(
        **{
            "aoi_orgware.company.worker": (
                "def work():\n    import aoi_orgware.ledger\n"
            ),
            "aoi_orgware.ledger": "VALUE = 1\n",
        }
    )
    findings = evaluate_import_governance(files, (_rule(),))
    assert [(item.rule_id, item.path) for item in findings] == [
        ("import_boundary:company-v1", "src/aoi_orgware/company/worker.py")
    ]


def test_stdlib_and_third_party_imports_are_ignored() -> None:
    files = _files(
        **{
            "aoi_orgware.company.worker": (
                "import ast\nimport external_library\nfrom json import loads\n"
            ),
        }
    )
    assert evaluate_import_governance(files, (_rule(),)) == ()


def test_relative_import_resolution_and_exact_submodule_cycle_edge() -> None:
    files = _files(
        **{
            "aoi_orgware.company.__init__": "from . import child\n",
            "aoi_orgware.company.child": "from . import helper\n",
            "aoi_orgware.company.helper": "from . import child\n",
        }
    )
    findings = evaluate_import_governance(files, (_rule(),))
    assert [item.rule_id for item in findings] == ["import_cycle:company-v1"]
    assert findings[0].path == "src/aoi_orgware/company/child.py"


def test_relative_from_symbol_does_not_create_a_cycle_edge() -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": "from . import function_symbol\n",
            "aoi_orgware.company.b": "from .a import VALUE\n",
        }
    )
    assert evaluate_import_governance(files, (_rule(),)) == ()


def test_class_body_is_module_executed_but_nested_methods_are_not() -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": (
                "class Loaded:\n"
                "    import aoi_orgware.company.b\n"
                "    def lazy(self):\n"
                "        import aoi_orgware.company.c\n"
            ),
            "aoi_orgware.company.b": "import aoi_orgware.company.a\n",
            "aoi_orgware.company.c": "import aoi_orgware.company.a\n",
        }
    )
    assert [item.rule_id for item in evaluate_import_governance(files, (_rule(),))] == [
        "import_cycle:company-v1"
    ]


@pytest.mark.parametrize("import_line", [
    "import aoi_orgware.pkg.child\n",
    "from aoi_orgware.pkg import child\n",
    "from aoi_orgware.pkg.child import VALUE\n",
])
def test_dotted_import_includes_new_package_init_but_not_initialized_parent(
    import_line: str,
) -> None:
    rule = _rule(
        source="aoi_orgware", allowed=("aoi_orgware",), rule_id="all-v1"
    )
    cross_package = _files(
        **{
            "aoi_orgware.__init__": "VALUE = 1\n",
            "aoi_orgware.outside.__init__": "VALUE = 1\n",
            "aoi_orgware.outside.a": import_line,
            "aoi_orgware.pkg.__init__": "import aoi_orgware.outside.a\n",
            "aoi_orgware.pkg.child": "VALUE = 1\n",
        }
    )
    assert [item.rule_id for item in evaluate_import_governance(cross_package, (rule,))] == [
        "import_cycle:all-v1"
    ]
    intra_package = _files(
        **{
            "aoi_orgware.__init__": "VALUE = 1\n",
            "aoi_orgware.pkg.__init__": "import aoi_orgware.pkg.child\n",
            "aoi_orgware.pkg.child": "import aoi_orgware.pkg\n",
        }
    )
    assert evaluate_import_governance(intra_package, (rule,)) == ()


@pytest.mark.parametrize("import_line", [
    "import aoi_orgware.pkg.child\n",
    "from aoi_orgware.pkg import child\n",
    "from aoi_orgware.pkg.child import VALUE\n",
])
def test_boundary_checks_package_initializers_for_all_dotted_literal_forms(
    import_line: str,
) -> None:
    rule = _rule(
        source="aoi_orgware.outside", allowed=("aoi_orgware.pkg.child",),
        rule_id="child-only-v1",
    )
    files = _files(
        **{
            "aoi_orgware.__init__": "VALUE = 1\n",
            "aoi_orgware.outside.__init__": "VALUE = 1\n",
            "aoi_orgware.outside.a": import_line,
            "aoi_orgware.pkg.__init__": "VALUE = 1\n",
            "aoi_orgware.pkg.child": "VALUE = 1\n",
        }
    )
    findings = evaluate_import_governance(files, (rule,))
    assert [item.rule_id for item in findings] == ["import_boundary:child-only-v1"]
    assert findings[0].path == "src/aoi_orgware/outside/a.py"


def test_boundary_does_not_report_an_already_initialized_intra_package_parent() -> None:
    rule = _rule(
        source="aoi_orgware.pkg", allowed=("aoi_orgware.pkg.child",),
        rule_id="sibling-child-v1",
    )
    files = _files(
        **{
            "aoi_orgware.__init__": "VALUE = 1\n",
            "aoi_orgware.pkg.__init__": "import aoi_orgware.pkg.child\n",
            "aoi_orgware.pkg.child": "VALUE = 1\n",
        }
    )
    assert evaluate_import_governance(files, (rule,)) == ()


def test_module_executed_try_block_contributes_a_cycle() -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": (
                "try:\n    import aoi_orgware.company.b\nexcept Exception:\n"
                "    pass\n"
            ),
            "aoi_orgware.company.b": "import aoi_orgware.company.a\n",
        }
    )
    assert [item.rule_id for item in evaluate_import_governance(files, (_rule(),))] == [
        "import_cycle:company-v1"
    ]


@pytest.mark.parametrize(("prelude", "condition"), [
    ("", "TYPE_CHECKING"),
    ("", "typing.TYPE_CHECKING"),
    ("", "not TYPE_CHECKING"),
    ("", "not typing.TYPE_CHECKING"),
    ("TYPE_CHECKING = True\n", "TYPE_CHECKING"),
    ("local_type_checking = True\n", "local_type_checking or TYPE_CHECKING"),
])
def test_every_type_checking_spelling_is_conservatively_cycle_covered(
    prelude: str, condition: str,
) -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": (
                f"{prelude}if {condition}:\n"
                "    import aoi_orgware.company.b\n"
                "else:\n"
                "    import aoi_orgware.company.c\n"
            ),
            "aoi_orgware.company.b": "import aoi_orgware.company.a\n",
            "aoi_orgware.company.c": "import aoi_orgware.company.a\n",
        }
    )
    findings = evaluate_import_governance(files, (_rule(),))
    assert [item.rule_id for item in findings] == ["import_cycle:company-v1"]
    assert findings[0].path == "src/aoi_orgware/company/a.py"


@pytest.mark.parametrize("control_flow", [
    "if condition:\n    import aoi_orgware.company.b\n",
    "try:\n    pass\nexcept Exception:\n    import aoi_orgware.company.b\n",
    "try:\n    pass\nfinally:\n    import aoi_orgware.company.b\n",
    "with context():\n    import aoi_orgware.company.b\n",
    "for item in items:\n    import aoi_orgware.company.b\n",
    "while condition:\n    import aoi_orgware.company.b\n",
    "match subject:\n    case _:\n        import aoi_orgware.company.b\n",
])
def test_every_required_module_executed_control_flow_block_is_traversed(
    control_flow: str,
) -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": control_flow,
            "aoi_orgware.company.b": "import aoi_orgware.company.a\n",
        }
    )
    assert [item.rule_id for item in evaluate_import_governance(files, (_rule(),))] == [
        "import_cycle:company-v1"
    ]


def test_type_checking_still_has_boundary_and_dynamic_imports_are_outside_literal_coverage() -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": (
                "if typing.TYPE_CHECKING:\n    import aoi_orgware.ledger\n"
                "import importlib\n"
                "importlib.import_module('aoi_orgware.ledger')\n"
                "__import__('aoi_orgware.ledger')\n"
            ),
            "aoi_orgware.ledger": "VALUE = 1\n",
        }
    )
    assert [item.rule_id for item in evaluate_import_governance(files, (_rule(),))] == [
        "import_boundary:company-v1"
    ]


@pytest.mark.parametrize("width", [1, 2, 3])
def test_cycle_detection_handles_self_two_and_three_node_cycles(width: int) -> None:
    files = _files(**{
        f"aoi_orgware.company.n{index}": (
            f"import aoi_orgware.company.n{(index + 1) % width}\n"
        )
        for index in range(width)
    })
    findings = evaluate_import_governance(files, (_rule(),))
    assert [item.rule_id for item in findings] == ["import_cycle:company-v1"]


def test_forbid_cycles_false_does_not_suppress_boundary_findings() -> None:
    files = _files(
        **{
            "aoi_orgware.company.a": (
                "import aoi_orgware.company.b\nimport aoi_orgware.ledger\n"
            ),
            "aoi_orgware.company.b": "import aoi_orgware.company.a\n",
            "aoi_orgware.ledger": "VALUE = 1\n",
        }
    )
    findings = evaluate_import_governance(files, (_rule(cycles=False),))
    assert [item.rule_id for item in findings] == ["import_boundary:company-v1"]


def test_malformed_utf8_duplicate_identity_rules_overlap_and_no_source_reject() -> None:
    with pytest.raises(FileGovernanceError, match="path must be text"):
        evaluate_import_governance(
            cast(Mapping[str, GitBlob], {1: GitBlob("100644", b"X = 1\n")}), (),
        )
    with pytest.raises(FileGovernanceError, match="strict UTF-8"):
        evaluate_import_governance(_files(**{"aoi_orgware.company.a": b"\xff"}), (_rule(),))
    with pytest.raises(FileGovernanceError, match="valid Python"):
        evaluate_import_governance(_files(**{"aoi_orgware.company.a": "if :\n"}), (_rule(),))
    with pytest.raises(FileGovernanceError, match="duplicate Python module"):
        evaluate_import_governance(_files(
            **{
                "aoi_orgware.company.x": "X = 1\n",
                "aoi_orgware.company.x.__init__": "X = 2\n",
            }
        ), ())
    with pytest.raises(FileGovernanceError, match="case-folding"):
        evaluate_import_governance(_files(
            **{
                "aoi_orgware.company.Foo": "X = 1\n",
                "aoi_orgware.company.foo": "X = 2\n",
            }
        ), ())
    with pytest.raises(FileGovernanceError, match="NFC"):
        evaluate_import_governance(
            _files(**{"aoi_orgware.company.e\u0301": "X = 1\n"}), (),
        )


def test_module_file_cannot_shadow_child_package_tree_or_casefold_equivalent() -> None:
    with pytest.raises(FileGovernanceError, match="shadows a Python package"):
        evaluate_import_governance(_files(
            **{
                "aoi_orgware.company.x": "VALUE = 1\n",
                "aoi_orgware.company.x.y": "VALUE = 2\n",
            }
        ), ())
    with pytest.raises(FileGovernanceError, match="shadows a Python package"):
        evaluate_import_governance(_files(
            **{
                "aoi_orgware.company.X": "VALUE = 1\n",
                "aoi_orgware.company.x.y": "VALUE = 2\n",
            }
        ), ())
    namespace_package = _files(**{"aoi_orgware.company.x.y": "VALUE = 1\n"})
    assert evaluate_import_governance(namespace_package, ()) == ()
    files = _files(**{"aoi_orgware.company.a": "X = 1\n"})
    with pytest.raises(FileGovernanceError, match="duplicate import-boundary rule"):
        evaluate_import_governance(files, (_rule(), _rule()))
    with pytest.raises(FileGovernanceError, match="overlapping"):
        evaluate_import_governance(files, (
            _rule(source="aoi_orgware.company", rule_id="one"),
            _rule(source="aoi_orgware.company.a", rule_id="two"),
        ))
    with pytest.raises(FileGovernanceError, match="no matching source"):
        evaluate_import_governance(files, (_rule(source="aoi_orgware.pd"),))


def test_relative_import_outside_the_top_level_package_rejects() -> None:
    files = _files(**{"aoi_orgware.company.a": "from ... import nowhere\n"})
    with pytest.raises(FileGovernanceError, match="outside its package"):
        evaluate_import_governance(files, (_rule(),))


def test_output_is_utf8_ordinal_and_deterministic() -> None:
    files = _files(
        **{
            "aoi_orgware.company.z": "import aoi_orgware.ledger\n",
            "aoi_orgware.company.a": "import aoi_orgware.ledger\n",
            "aoi_orgware.ledger": "VALUE = 1\n",
        }
    )
    first = evaluate_import_governance(files, (_rule(),))
    second = evaluate_import_governance(dict(reversed(tuple(files.items()))), (_rule(),))
    assert first == second
    assert [item.path for item in first] == [
        "src/aoi_orgware/company/a.py",
        "src/aoi_orgware/company/z.py",
    ]
