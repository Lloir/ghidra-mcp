"""PyGhidra JVM ownership and lifecycle for opened programs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import sys
from threading import RLock
from time import monotonic
from types import ModuleType
from typing import Any, Iterator
from uuid import uuid4


class WorkspaceError(RuntimeError):
    """A program workspace operation failed."""


_MINIMUM_GHIDRA_VERSION = (12, 1, 2)


def _read_ghidra_version(install_dir: Path) -> tuple[int, int, int]:
    properties = install_dir / "Ghidra" / "application.properties"
    try:
        lines = properties.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise WorkspaceError(f"Unable to determine Ghidra version: failed to read {properties}") from error
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == "application.version":
            match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[-._].*)?", value.strip())
            if match is not None:
                major, minor, patch = match.groups()
                return int(major), int(minor), int(patch or 0)
            break
    raise WorkspaceError(
        f"Unable to determine Ghidra version: {properties} is missing a valid application.version"
    )


@dataclass(slots=True)
class _ProgramRecord:
    path: Path
    context: Any
    api: Any


class GhidraRuntime:
    def __init__(
        self,
        install_dir: Path,
        *,
        pyghidra_module: ModuleType | Any | None = None,
        analysis_timeout_seconds: int = 300,
    ) -> None:
        self.install_dir = install_dir.resolve()
        if pyghidra_module is None:
            import pyghidra

            pyghidra_module = pyghidra
        self.pyghidra = pyghidra_module
        self.analysis_timeout_seconds = analysis_timeout_seconds
        self._launcher: object | None = None
        self._lock = RLock()

    def ensure_started(self) -> object:
        with self._lock:
            if self._launcher is None:
                if not self.install_dir.is_dir():
                    raise WorkspaceError(f"Ghidra installation directory does not exist: {self.install_dir}")
                version = _read_ghidra_version(self.install_dir)
                if version < _MINIMUM_GHIDRA_VERSION:
                    detected = ".".join(str(part) for part in version)
                    raise WorkspaceError(
                        f"Ghidra {detected} is below the minimum supported version 12.1.2"
                    )
                self._launcher = self.pyghidra.start(install_dir=self.install_dir)
            return self._launcher

    def analyze(self, program: Any) -> None:
        self.ensure_started()
        deadline = monotonic() + self.analysis_timeout_seconds
        monitor = self.pyghidra.task_monitor(self.analysis_timeout_seconds)
        self.pyghidra.analyze(program, monitor=monitor)
        if monitor.isCancelled() and monotonic() >= deadline:
            raise TimeoutError(f"Ghidra auto-analysis exceeded {self.analysis_timeout_seconds} seconds")

    def program_context(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        analyze: bool,
    ) -> Any:
        test_factory = getattr(self.pyghidra, "_program_context_factory", None)
        if test_factory is not None:
            return test_factory(
                binary,
                project_location=project_location,
                project_name=project_name,
                analyze=analyze,
            )
        return self._modern_program_context(
            binary,
            project_location=project_location,
            project_name=project_name,
            analyze=analyze,
        )

    @contextmanager
    def _modern_program_context(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        analyze: bool,
    ) -> Iterator[Any]:
        location = project_location or binary.parent
        name = project_name or f"{binary.name}_ghidra"
        project = self.pyghidra.open_project(location, name, create=True)
        project_path = f"/{binary.name}"
        try:
            existing_context = self.pyghidra.program_context(project, project_path)
            try:
                program = existing_context.__enter__()
            except FileNotFoundError:
                pass
            else:
                try:
                    if analyze:
                        self.analyze(program)
                    yield self._flat_api(program)
                except BaseException:
                    if not existing_context.__exit__(*sys.exc_info()):
                        raise
                else:
                    existing_context.__exit__(None, None, None)
                return

            results = (
                self.pyghidra.program_loader()
                .source(str(binary))
                .project(project)
                .name(binary.name)
                .load()
            )
            consumer = self._new_consumer()
            program = results.getPrimaryDomainObject(consumer)
            try:
                if analyze:
                    self.analyze(program)
                results.save(self.pyghidra.task_monitor())
                yield self._flat_api(program)
            finally:
                program.release(consumer)
                results.close()
        finally:
            project.close()

    def program_context_raw(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        language_id: str,
        compiler_id: str,
        base_address: str,
        analyze: bool,
    ) -> Any:
        test_factory = getattr(self.pyghidra, "_program_context_raw_factory", None)
        if test_factory is not None:
            return test_factory(
                binary,
                project_location=project_location,
                project_name=project_name,
                language_id=language_id,
                compiler_id=compiler_id,
                base_address=base_address,
                analyze=analyze,
            )
        return self._modern_program_context_raw(
            binary,
            project_location=project_location,
            project_name=project_name,
            language_id=language_id,
            compiler_id=compiler_id,
            base_address=base_address,
            analyze=analyze,
        )

    @contextmanager
    def _modern_program_context_raw(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        language_id: str,
        compiler_id: str,
        base_address: str,
        analyze: bool,
    ) -> Iterator[Any]:
        """Load a raw binary that cannot be auto-recognized (e.g. a firmware image)
        with an explicit language and base address.

        Shares the "existing session first" semantics of ``_modern_program_context``:
        if a program is already imported at this project path (whether created
        earlier by this method or by ``program_open``), it is reused rather than
        re-imported.
        """

        location = project_location or binary.parent
        name = project_name or f"{binary.name}_ghidra"
        project = self.pyghidra.open_project(location, name, create=True)
        project_path = f"/{binary.name}"
        try:
            existing_context = self.pyghidra.program_context(project, project_path)
            try:
                program = existing_context.__enter__()
            except FileNotFoundError:
                pass
            else:
                try:
                    if analyze:
                        self.analyze(program)
                    yield self._flat_api(program)
                except BaseException:
                    if not existing_context.__exit__(*sys.exc_info()):
                        raise
                else:
                    existing_context.__exit__(None, None, None)
                return

            from ghidra.app.util.opinion import BinaryLoader

            results = (
                self.pyghidra.program_loader()
                .source(str(binary))
                .project(project)
                .name(binary.name)
                .loaders(BinaryLoader)
                .language(language_id)
                .compiler(compiler_id)
                .load()
            )
            consumer = self._new_consumer()
            program = results.getPrimaryDomainObject(consumer)
            try:
                self._rebase(program, base_address)
                if analyze:
                    self.analyze(program)
                results.save(self.pyghidra.task_monitor())
                yield self._flat_api(program)
            finally:
                program.release(consumer)
                results.close()
        finally:
            project.close()

    def _rebase(self, program: Any, base_address: str) -> None:
        """Move a freshly imported program to the caller-supplied base address.

        BinaryLoader's "Base Address" import option cannot be set reliably
        through the string-pair importer API (confirmed by live testing), so
        this uses the standard workaround instead: import at the default base
        (0), then call ``Program.setImageBase`` inside a transaction to shift
        the whole program.
        """

        normalized = base_address[2:] if base_address.lower().startswith("0x") else base_address
        address_factory = program.getAddressFactory()
        target = address_factory.getDefaultAddressSpace().getAddress(normalized)
        transaction_id = program.startTransaction("ghidra-mcp: set image base")
        committed = False
        try:
            program.setImageBase(target, True)
            committed = True
        finally:
            program.endTransaction(transaction_id, committed)

    def _flat_api(self, program: Any) -> Any:
        from ghidra.program.flatapi import FlatProgramAPI

        return FlatProgramAPI(program)

    def _new_consumer(self) -> Any:
        from java.lang import Object

        return Object()

    def save(self, api: Any) -> None:
        """Persist the current program database before the tool reports success."""

        api.getCurrentProgram().save("ghidra-mcp", self.pyghidra.task_monitor())


def _persistent_project_name(binary: Path) -> str:
    digest = sha256()
    digest.update(str(binary).encode("utf-8"))
    digest.update(b"\0")
    with binary.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"{binary.name}-{digest.hexdigest()[:20]}"


class ProgramWorkspace:
    def __init__(
        self,
        runtime: GhidraRuntime,
        *,
        project_location: Path | None = None,
        input_root: Path | None = None,
    ) -> None:
        self.runtime = runtime
        self.project_location = project_location.resolve() if project_location is not None else None
        self.input_root = input_root.resolve() if input_root is not None else None
        if self.project_location is not None:
            self.project_location.mkdir(parents=True, exist_ok=True)
        self._programs: dict[str, _ProgramRecord] = {}
        self._lock = RLock()

    def resolve_input(self, binary_path: Path) -> Path:
        """Validate and resolve an input path; shared by tools that need to read
        raw bytes directly, not just by program import."""

        binary = binary_path.resolve()
        if self.input_root is not None and not binary.is_relative_to(self.input_root):
            raise WorkspaceError(f"input path is outside the allowed input root: {self.input_root}")
        if not binary.is_file():
            raise WorkspaceError(f"input binary does not exist: {binary}")
        return binary

    def open(
        self,
        binary_path: Path,
        *,
        project_location: Path | None = None,
        analyze: bool = True,
    ) -> str:
        binary = self.resolve_input(binary_path)
        project_name = _persistent_project_name(binary)
        self.runtime.ensure_started()
        effective_location = (
            project_location.resolve() if project_location is not None else self.project_location
        )
        context = self.runtime.program_context(
            binary,
            project_location=effective_location,
            project_name=project_name,
            analyze=analyze,
        )
        api = context.__enter__()
        try:
            if analyze:
                self.runtime.save(api)
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise
        program_id = uuid4().hex
        with self._lock:
            self._programs[program_id] = _ProgramRecord(binary, context, api)
        return program_id

    def open_raw(
        self,
        binary_path: Path,
        *,
        language_id: str,
        base_address: str,
        compiler_id: str = "default",
        project_location: Path | None = None,
        analyze: bool = True,
    ) -> str:
        """Open a raw binary that ``program_open``'s auto-detection failed on,
        using an explicit language and base address.

        Project naming and location exactly match ``open`` (the same binary
        path always maps to the same persistent project), so whichever of
        ``open`` or ``open_raw`` is called afterwards finds the same already-
        imported program, never re-importing it.
        """

        binary = self.resolve_input(binary_path)
        project_name = _persistent_project_name(binary)
        self.runtime.ensure_started()
        effective_location = (
            project_location.resolve() if project_location is not None else self.project_location
        )
        context = self.runtime.program_context_raw(
            binary,
            project_location=effective_location,
            project_name=project_name,
            language_id=language_id,
            compiler_id=compiler_id,
            base_address=base_address,
            analyze=analyze,
        )
        api = context.__enter__()
        try:
            if analyze:
                self.runtime.save(api)
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise
        program_id = uuid4().hex
        with self._lock:
            self._programs[program_id] = _ProgramRecord(binary, context, api)
        return program_id

    def get(self, program_id: str) -> Any:
        with self._lock:
            try:
                return self._programs[program_id].api
            except KeyError as error:
                raise WorkspaceError(f"program session does not exist: {program_id}") from error

    def list_open(self) -> list[dict[str, str]]:
        with self._lock:
            return [
                {"program_id": program_id, "path": str(record.path)}
                for program_id, record in self._programs.items()
            ]

    def describe(self, program_id: str) -> dict[str, str]:
        program = self.get(program_id).getCurrentProgram()
        return {
            "program_id": program_id,
            "name": str(program.getName()),
            "language": str(program.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": str(program.getImageBase()),
            "format": str(program.getExecutableFormat()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
        }

    def close(self, program_id: str) -> None:
        with self._lock:
            try:
                record = self._programs[program_id]
            except KeyError as error:
                raise WorkspaceError(f"program session does not exist: {program_id}") from error
            self.runtime.save(record.api)
            del self._programs[program_id]
            record.context.__exit__(None, None, None)

    def save(self, program_id: str) -> None:
        self.runtime.save(self.get(program_id))

    def analyze(self, program_id: str) -> None:
        self.runtime.analyze(self.get(program_id).getCurrentProgram())

    def close_all(self) -> None:
        with self._lock:
            program_ids = tuple(self._programs)
        failures: list[BaseException] = []
        for program_id in program_ids:
            try:
                self.close(program_id)
            except BaseException as error:
                failures.append(error)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("failed to close one or more program sessions", failures)
