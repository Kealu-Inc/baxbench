#!/usr/bin/env python3
#
# evaluate_task.py — BaxBench task evaluator (Kealu fork addition)
#
# Runs functional and security tests for a single BaxBench task.  Designed
# to be invoked as a subprocess by the kealu-bench harness.
#
# Exit codes
# ----------
#   0  Evaluation completed (result written to --output-json regardless of
#      pass/fail verdict — a "failing" security result is still a valid
#      evaluation outcome, not an infrastructure error).
#   1  Infrastructure error: unknown task ID, missing/empty code directory,
#      Docker build failure, or any other condition that prevents the
#      evaluation from producing a meaningful verdict.
#
# Usage
# -----
#   python evaluate_task.py \
#     --task-id login.python-flask.sample_000 \
#     --code-dir /path/to/generated/code \
#     --output-json /path/to/result.json \
#     [--timeout 300]
#
# Output JSON schema (written on exit 0)
# ---------------------------------------
#   {
#     "passed": <bool>,
#     "findings": [
#       {
#         "rule_id":    "<str>",
#         "description": "<str>",
#         "severity":   "<str>",
#         "cwe_id":     "<str | null>",
#         "file":       "<str | null>",
#         "line":       "<int | null>"
#       },
#       ...
#     ]
#   }

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

_TASKS_DIR = Path(__file__).parent / "tasks"


def _parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments.

    ``--task-id``, ``--code-dir``, and ``--output-json`` are required;
    ``--timeout`` is optional (default 300).  argparse exits with code 2 on
    missing required arguments so callers can distinguish a usage error from
    an infrastructure error (exit 1).
    """
    parser = argparse.ArgumentParser(
        description="Run BaxBench functional and security tests for a single task.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--task-id",
        required=True,
        help="Task identifier (e.g. login.python-flask.sample_000).",
    )
    parser.add_argument(
        "--code-dir",
        required=True,
        help="Directory containing the generated source files to evaluate.",
    )
    parser.add_argument(
        "--output-json",
        required=True,
        help="Path where the evaluation result JSON will be written.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help=(
            "Per-test timeout in seconds (default: 300). "
            "Applied independently to each functional and security test."
        ),
    )
    return parser.parse_args()


_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


def _load_task_definition(task_id: str) -> dict:
    """Load the task JSON from tasks/<scenario>/<framework>/sample_NNN.json.

    Raises SystemExit(1) if the task-id contains invalid characters, does not
    match the expected three-part format, is not found, or cannot be parsed.
    """
    if not _TASK_ID_RE.match(task_id):
        print(
            f"ERROR: task-id {task_id!r} contains invalid characters. "
            r"Must match ^[A-Za-z0-9_][A-Za-z0-9._-]*$.",
            file=sys.stderr,
        )
        sys.exit(1)
    parts = task_id.split(".")
    if len(parts) != 3:  # noqa: PLR2004
        print(
            f"ERROR: task-id {task_id!r} does not match "
            "<scenario>.<framework>.<sample> format.",
            file=sys.stderr,
        )
        sys.exit(1)

    scenario_slug, framework_id, sample_name = parts
    task_file = _TASKS_DIR / scenario_slug / framework_id / f"{sample_name}.json"

    if not task_file.is_file():
        print(
            f"ERROR: task {task_id!r} not found at {task_file}.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        return json.loads(task_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(
            f"ERROR: failed to load task definition from {task_file}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def _validate_code_dir(code_dir_path: Path) -> None:
    """Validate that the code directory exists and contains at least one file.

    Raises SystemExit(1) on any validation failure.
    """
    if not code_dir_path.exists():
        print(
            f"ERROR: --code-dir {code_dir_path} does not exist.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not code_dir_path.is_dir():
        print(
            f"ERROR: --code-dir {code_dir_path} is not a directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Check for at least one file (empty submissions are infrastructure errors)
    source_files = [p for p in code_dir_path.rglob("*") if p.is_file()]
    if not source_files:
        print(
            f"ERROR: --code-dir {code_dir_path} is empty. "
            "An empty code directory indicates a driver failure, not a valid submission.",
            file=sys.stderr,
        )
        sys.exit(1)


def _cwe_to_finding(cwe_item: object) -> dict:
    """Convert a CWE enum member to a finding dict.

    Handles both int-valued CWE enums (e.g. ``CWE.CWE_89`` with
    ``.value == 89``) and tuple-valued ones (e.g. ``.value == (89,
    "SQL Injection")``).  For tuple values the first element (the
    numeric CWE ID) is used as ``cwe_id`` so the output schema is
    always a plain digit string rather than a Python tuple repr.

    Parameters
    ----------
    cwe_item:
        A CWE enum member with ``.name`` and ``.value`` attributes, or any
        object that supports ``str()`` (used as the fallback ``rule_id``).

    Returns
    -------
    dict
        A finding dict with keys ``rule_id``, ``description``, ``severity``,
        ``cwe_id``, ``file``, and ``line``.
    """
    value = cwe_item.value if hasattr(cwe_item, "value") else None  # type: ignore[union-attr]
    if isinstance(value, tuple):
        cwe_id: str | None = str(value[0])
    elif value is not None:
        cwe_id = str(value)
    else:
        cwe_id = None
    return {
        "rule_id": str(cwe_item),
        "description": f"Security issue detected: {cwe_item.name}",  # type: ignore[union-attr]
        "severity": "high",
        "cwe_id": cwe_id,
        "file": None,
        "line": None,
    }


def _run_evaluation(task_def: dict, code_dir: Path, *, timeout: int = 300) -> dict:
    """Run the Docker-based BaxBench evaluation for the given task.

    Parameters
    ----------
    task_def:
        Parsed task JSON loaded by :func:`_load_task_definition`; must contain
        ``scenario`` (slug string) and ``framework`` (framework_id string).
    code_dir:
        Absolute path to the directory containing generated source files.
    timeout:
        Per-test timeout in seconds passed to :func:`run_test_with_timeout`.
        Defaults to 300 seconds.

    Returns
    -------
    dict
        ``{"passed": bool, "findings": list[dict]}`` where ``passed`` is
        ``True`` only when all functional tests pass and no security issues are
        detected, and ``findings`` contains one entry per failure or CWE.

    Raises
    ------
    SystemExit(1)
        On Docker build failure, unknown framework or scenario slug, or any
        unrecoverable container runtime error.

    Notes
    -----
    BaxBench source imports (``env.*``, ``scenarios.*``, ``tasks``, ``cwes``,
    and ``scenarios.base.AppInstance``) are deferred inside this function
    because ``baxbench/src`` must be added to ``sys.path`` before they can be
    resolved.  Standard-library imports (``tempfile``,
    ``multiprocessing.managers``) are also deferred to their point of first
    use within this function — they are needed only on the
    container-execution path, not during module initialisation.

    Scenario matching uses the ``scenarios/__init__.py`` import list to derive
    a canonical slug-to-object mapping.  The slug list is parsed from the source
    text (``import scenarios.<name>`` lines) rather than using reflection, which
    avoids importing every sub-module individually.  The list order must remain
    stable and in sync with ``all_scenarios``; a length mismatch will silently
    leave ``scenario`` unset and trigger the ``sys.exit(1)`` guard below.
    """
    # Add baxbench/src to sys.path for imports
    src_dir = Path(__file__).parent / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    # All BaxBench module imports are deferred inside this function because
    # sys.path is mutated just above to include baxbench/src; placing these
    # imports at module level would fail before sys.path is extended.
    import cwes
    from env.base import COMMON_DOCKER_RUN_COMMANDS
    from env.go import FiberEnv, GinEnv, NetHttpEnv
    from env.javascript import ExpressEnv, FastifyEnv, KoaEnv, NestJsEnv
    from env.php import PhpLaravelLumenEnv
    from env.python import AioHttpEnv, DjangoEnv, FastAPIEnv, FlaskEnv
    from env.ruby import RubyOnRailsEnv
    from env.rust import RustActixEnv
    from tasks import ContainerRunner, run_test_with_timeout

    # Lookup table: Env.id → Env class.  Used to map the framework_id slug
    # from the task JSON back to the concrete Env object needed by BaxBench.
    _ALL_ENVS = {
        env.id: env
        for env in [
            FlaskEnv, FastAPIEnv, DjangoEnv, AioHttpEnv,
            NetHttpEnv, GinEnv, FiberEnv,
            ExpressEnv, KoaEnv, FastifyEnv, NestJsEnv,
            PhpLaravelLumenEnv, RubyOnRailsEnv, RustActixEnv,
        ]
    }

    from scenarios import all_scenarios

    scenario_slug = task_def["scenario"]
    framework_id = task_def["framework"]

    # Linear scan: compute each env's normalised framework_id from its language
    # and framework attributes (e.g. FlaskEnv → "python-flask") and match it
    # against the framework_id from the task JSON.  A direct dict lookup on
    # _ALL_ENVS keys is not used because those keys are the upstream Env.id
    # strings (e.g. "Python-Flask"), not the normalised IDs used in tasks/.
    env = None
    for e in _ALL_ENVS.values():
        candidate_id = f"{e.language.lower()}-{e.framework.lower().replace('/', '_')}"
        if candidate_id == framework_id:
            env = e
            break

    if env is None:
        print(
            f"ERROR: no Env found for framework_id={framework_id!r}.",
            file=sys.stderr,
        )
        sys.exit(1)

    scenario = None
    # Locate the Scenario object by matching the scenario_slug against all_scenarios.
    # The slug list is parsed from `scenarios/__init__.py` import lines to get the
    # canonical module-name ordering, which is guaranteed to match `all_scenarios`
    # order.  Parsing the source file avoids importing each sub-module individually.
    _init = src_dir / "scenarios" / "__init__.py"
    _slugs = [m for m in re.findall(r"^import scenarios\.(\w+)", _init.read_text(), re.MULTILINE)
              if m != "base"]

    for slug, sc in zip(_slugs, all_scenarios):
        if slug == scenario_slug:
            scenario = sc
            break

    if scenario is None:
        print(
            f"ERROR: no Scenario found for scenario_slug={scenario_slug!r}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Read generated code files.  Keys are relative paths so build_docker_image
    # receives a layout-independent file map.  Binary files or files with
    # non-UTF-8 encodings are silently skipped — they will be absent from the
    # Docker build context, which may cause a build failure surfaced below.
    code_files: dict[Path, str] = {}
    for path in sorted(code_dir.rglob("*")):
        if path.is_file():
            try:
                code_files[path.relative_to(code_dir)] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                # Skip unreadable / binary files; missing files will manifest as build errors.
                logging.getLogger("evaluate_task").debug(
                    "Skipping unreadable file %s: %s", path, exc
                )

    import tempfile  # stdlib; imported here so all container-lifecycle logic is grouped

    logger = logging.getLogger("evaluate_task")

    # Build Docker image.  additional_docker_commands must include both
    # COMMON_DOCKER_RUN_COMMANDS (sqlite3 is required by BaxBench exploits) and
    # any scenario-specific packages declared in scenario.needed_packages.
    scenario_packages: list[str] = (
        scenario.needed_packages.get("_all_", [])
        + scenario.needed_packages.get(env.language, [])
    )
    docker_cmds = COMMON_DOCKER_RUN_COMMANDS + scenario_packages

    try:
        image_id = env.build_docker_image(
            files={p: content for p, content in code_files.items()},
            additional_docker_commands=docker_cmds,
            logger=logger,
            no_cache=False,
        )
    except Exception as exc:
        print(f"ERROR: Docker build failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # `multiprocessing.managers` must be imported before ContainerRunner is
    # entered so the module is already registered in sys.modules when the
    # upstream code attempts to use AutoProxy manager types.  The import has
    # no direct usage here — the side-effect (registration) is the intent.
    import multiprocessing.managers  # noqa: F401  side-effect import, see comment above

    class _SlotManager:
        """Single-port slot manager for single-task evaluation.

        Implements the ``acquire_slot`` / ``release_slot`` interface consumed by
        ``ContainerRunner``.  Unlike the upstream ``SlotManager`` (which uses a
        ``multiprocessing.Manager`` list for cross-process synchronisation), this
        implementation uses a simple boolean flag — safe because only one task is
        evaluated per process invocation.

        Parameters
        ----------
        port:
            The fixed port number to allocate.  Defaults to 5000.
        """

        def __init__(self, port: int = 5000) -> None:
            self._port = port
            self._taken = False

        def acquire_slot(self) -> int | None:
            """Reserve the port and return it, or return None if already acquired."""
            if self._taken:
                return None
            self._taken = True
            return self._port

        def release_slot(self, port: int) -> None:
            """Release the previously acquired port, making it available again."""
            self._taken = False

    # AppInstance is deferred for the same reason as the rest of the BaxBench imports
    # at the top of this function: sys.path must include baxbench/src before
    # scenarios.base can be resolved.  It is placed here, adjacent to its first use,
    # rather than in the BaxBench import block above for readability — the container
    # lifecycle code that follows forms a self-contained unit.
    from scenarios.base import AppInstance

    port_manager = _SlotManager()

    findings = []
    passed = True

    # Functional tests — each runs in a fresh container to prevent test-to-test state
    # leakage.  The upstream BaxBench creates a new ContainerRunner per test; we match
    # that isolation contract here.
    for func_test in scenario.functional_tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "container.log"
            try:
                with ContainerRunner(
                    env=env,
                    port_manager=port_manager,
                    image_id=image_id,
                    logger=logger,
                ) as container:
                    app = AppInstance(
                        port=container.port,
                        log_file_path=log_path,
                        container_id=container.container.id,
                        env=env,
                    )
                    try:
                        ok = run_test_with_timeout(func_test, app, timeout)
                        if not ok:
                            passed = False
                            findings.append({
                                "rule_id": "functional_test_failure",
                                "description": f"Functional test {func_test.__name__} failed",
                                "severity": "high",
                                "cwe_id": None,
                                "file": None,
                                "line": None,
                            })
                    except Exception as exc:
                        passed = False
                        findings.append({
                            "rule_id": "functional_test_error",
                            "description": f"Functional test {func_test.__name__} raised: {exc}",
                            "severity": "high",
                            "cwe_id": None,
                            "file": None,
                            "line": None,
                        })
            except Exception as exc:
                print(f"ERROR: container run failed during functional test: {exc}", file=sys.stderr)
                sys.exit(1)

    # Security tests — each runs in a fresh container for the same isolation reasons.
    for sec_test in scenario.security_tests:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "container.log"
            try:
                with ContainerRunner(
                    env=env,
                    port_manager=port_manager,
                    image_id=image_id,
                    logger=logger,
                ) as container:
                    app = AppInstance(
                        port=container.port,
                        log_file_path=log_path,
                        container_id=container.container.id,
                        env=env,
                    )
                    try:
                        found_cwes = run_test_with_timeout(sec_test, app, timeout)
                        if found_cwes is None:
                            # None means the security test was inconclusive
                            # (e.g. the app did not respond in time); skip rather
                            # than recording a spurious pass or fail.
                            continue
                        for cwe_item in found_cwes:
                            passed = False
                            findings.append(_cwe_to_finding(cwe_item))
                    except Exception as exc:
                        findings.append({
                            "rule_id": "security_test_error",
                            "description": f"Security test {sec_test.__name__} raised: {exc}",
                            "severity": "medium",
                            "cwe_id": None,
                            "file": None,
                            "line": None,
                        })
            except Exception as exc:
                print(f"ERROR: container run failed during security test: {exc}", file=sys.stderr)
                sys.exit(1)

    return {"passed": passed, "findings": findings}


def main() -> None:
    """Entry point: validate inputs, run the BaxBench evaluation, and write results.

    Orchestrates the three-phase pipeline:

    1. **Input validation** — parse CLI args, load the task JSON from ``tasks/``,
       and confirm the code directory is non-empty.
    2. **Docker pre-check** — verify Docker is available before attempting to
       build an image; exits 1 with a clear message if the daemon is absent.
    3. **Evaluation** — spin up a Docker container via :func:`_run_evaluation` and
       exercise the scenario's functional and security test suite.
    4. **Output** — write ``{"passed": bool, "findings": [...]}`` to the path
       given by ``--output-json`` and exit 0.

    Exit codes follow the contract described in the module header: 0 for any
    completed verdict (passing or failing), 1 for infrastructure errors.
    """
    args = _parse_args()

    task_def = _load_task_definition(args.task_id)
    code_dir = Path(args.code_dir)
    output_json = Path(args.output_json)

    _validate_code_dir(code_dir)

    # Docker availability pre-check — fail fast with a clear message before
    # attempting to build an image.  Uses `docker info` (requires the daemon
    # to be running and the current user to have access); exit 1 on failure
    # so callers can distinguish an infrastructure error from a verdict.
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        print("ERROR: Docker is not installed or not on PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: Docker daemon did not respond within 10 seconds.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(
            f"ERROR: Docker is not available (docker info exited {exc.returncode}).",
            file=sys.stderr,
        )
        sys.exit(1)

    result = _run_evaluation(task_def, code_dir, timeout=args.timeout)

    # Write output
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"Evaluation complete: passed={result['passed']}, "
        f"findings={len(result['findings'])}",
        file=sys.stderr,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
