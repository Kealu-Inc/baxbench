#
# Copyright 2026 Kealu Inc. All rights reserved.
# Licensed under the Kealu Vector License v1.0 — PATENT PENDING
#
"""Export BaxBench task JSON files from the upstream scenario definitions.

Usage (run from the repo root, with baxbench/ already cloned):

    python scripts/export_tasks.py

The script reads the baxbench/ checkout relative to the repository root,
imports all 28 × 14 = 392 scenario×environment combinations, generates the
natural-language code-generation prompt for each cell, and writes one JSON
file per cell under baxbench/tasks/.

Output layout::

    baxbench/tasks/
      <scenario_slug>/
        <framework_id>/
          sample_000.json    # {"task_id": "…", "scenario": "…", "framework": "…",
                             #  "language": "…", "spec": "…"}

Each JSON file contains exactly one task (the canonical sample for its cell).
Multiple samples per cell are not needed for the initial PoC — the single
``sample_000`` sample is the full benchmark task.

Naming conventions
------------------
* ``scenario_slug``: snake_case module name from ``scenarios/__init__.py``
  (e.g. ``click_count``, ``credit_card_service``).
* ``framework_id``: ``{language.lower()}-{framework.lower()}`` with ``/``
  replaced by ``_`` (e.g. ``go-net_http``, ``python-flask``).
* ``task_id``: ``{scenario_slug}.{framework_id}.sample_000``
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — add baxbench/src to sys.path so the upstream modules import
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_BAXBENCH_SRC = _REPO_ROOT / "baxbench" / "src"
_TASKS_OUT = _REPO_ROOT / "baxbench" / "tasks"

if not _BAXBENCH_SRC.is_dir():
    print(
        f"ERROR: baxbench/src not found at {_BAXBENCH_SRC}.\n"
        "Clone the fork first: bash scripts/setup_baxbench.sh",
        file=sys.stderr,
    )
    sys.exit(1)

sys.path.insert(0, str(_BAXBENCH_SRC))


def _slugify_framework(language: str, framework: str) -> str:
    """Return the framework_id slug: ``{language_lower}-{framework_lower_no_slash}``."""
    return f"{language.lower()}-{framework.lower().replace('/', '_')}"


def _extract_scenario_slugs(scenarios_init: Path) -> list[str]:
    """Parse ``scenarios/__init__.py`` and return slug list in canonical order."""
    content = scenarios_init.read_text(encoding="utf-8")
    slugs = re.findall(r"^import scenarios\.(\w+)", content, re.MULTILINE)
    return [s for s in slugs if s != "base"]


def main() -> None:  # noqa: PLR0912 — nested loops over 28 scenarios × 14 frameworks; splitting into helpers would obscure the single-pass generation logic without reducing conceptual complexity
    """Generate 392 task JSON files and write them to baxbench/tasks/."""
    # ---- Dynamic imports (requires baxbench/src on sys.path) ----
    from env.go import FiberEnv, GinEnv, NetHttpEnv
    from env.javascript import ExpressEnv, FastifyEnv, KoaEnv, NestJsEnv
    from env.php import PhpLaravelLumenEnv
    from env.python import AioHttpEnv, DjangoEnv, FastAPIEnv, FlaskEnv
    from env.ruby import RubyOnRailsEnv
    from env.rust import RustActixEnv
    from scenarios import all_scenarios

    all_envs = [
        FlaskEnv,
        FastAPIEnv,
        DjangoEnv,
        AioHttpEnv,
        NetHttpEnv,
        GinEnv,
        FiberEnv,
        ExpressEnv,
        KoaEnv,
        FastifyEnv,
        NestJsEnv,
        PhpLaravelLumenEnv,
        RubyOnRailsEnv,
        RustActixEnv,
    ]

    scenarios_init = _BAXBENCH_SRC / "scenarios" / "__init__.py"
    slugs = _extract_scenario_slugs(scenarios_init)

    if len(slugs) != len(all_scenarios):
        print(
            f"ERROR: slug count ({len(slugs)}) != scenario count ({len(all_scenarios)})",
            file=sys.stderr,
        )
        sys.exit(1)

    _TASKS_OUT.mkdir(parents=True, exist_ok=True)

    written = 0
    errors = 0

    for scenario, scenario_slug in zip(all_scenarios, slugs, strict=True):
        for env in all_envs:
            framework_id = _slugify_framework(env.language, env.framework)
            task_id = f"{scenario_slug}.{framework_id}.sample_000"

            try:
                # build_prompt(env, spec_format, examples, include_cwe_hints):
                #   "openapi"   — use the OpenAPI spec variant (vs "text")
                #   "none"      — omit code examples from the prompt
                #   False       — do not embed CWE hint text in the prompt
                # These values produce the natural-language spec consumed by
                # BaxTask.spec without leaking security-hint information.
                spec = scenario.build_prompt(env, "openapi", "none", False)
            except Exception as exc:  # noqa: BLE001 — broad catch intentional: build_prompt can raise heterogeneous errors from diverse scenario implementations; each is logged and the cell is skipped rather than aborting the full export
                print(f"  ERROR building prompt for {task_id}: {exc}", file=sys.stderr)
                errors += 1
                continue

            cell_dir = _TASKS_OUT / scenario_slug / framework_id
            cell_dir.mkdir(parents=True, exist_ok=True)

            task_data = {
                "task_id": task_id,
                "scenario": scenario_slug,
                "framework": framework_id,
                "language": env.language.lower(),
                "spec": spec,
            }

            out_path = cell_dir / "sample_000.json"
            out_path.write_text(
                json.dumps(task_data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            written += 1

    print(f"Wrote {written} task JSON files to {_TASKS_OUT}", file=sys.stderr)
    if errors:
        print(f"WARNING: {errors} task(s) failed to export", file=sys.stderr)
        sys.exit(1)
    expected = len(all_scenarios) * len(all_envs)
    if written != expected:
        print(
            f"ERROR: expected {expected} tasks, wrote {written}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Export complete: {written}/{expected} tasks", file=sys.stderr)


if __name__ == "__main__":
    main()
