"""
Python parser for pip, Poetry, Pipenv, and Conda environments.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

import asyncio
import httpx
import yaml

try:  # Python 3.11+
    import tomllib as toml
except Exception:  # Fallback
    try:
        import toml  # type: ignore
    except Exception:  # pragma: no cover
        toml = None  # TOML parsing unavailable

from ..models import Package, Dependency, DependencyType
from ..detectors import Language, PackageManager
from .base import BaseParser


class PythonParser(BaseParser):
    """Parser for Python projects across multiple package managers."""

    def __init__(self, package_manager: PackageManager = PackageManager.PIP):
        super().__init__(Language.PYTHON, package_manager)
        self.pypi_api_json = "https://pypi.org/pypi"

    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse Python manifests (requirements.txt, pyproject.toml, Pipfile, environment.yml).

        Returns only direct dependencies. Use parse_lockfile for full tree when available.
        """
        filename = manifest_path.name.lower()

        if filename in {"requirements.txt", "requirements.in", "requirements-dev.txt"}:
            return self._parse_requirements(manifest_path)
        if filename == "pyproject.toml":
            return self._parse_pyproject(manifest_path)
        if filename == "pipfile":
            return self._parse_pipfile_manifest(manifest_path)
        if filename in {"environment.yml", "environment.yaml"}:
            return self._parse_conda_environment(manifest_path)

        # Unsupported manifest treated as empty
        return []

    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse Python lockfiles for complete dependency trees with pinned versions."""
        filename = lockfile_path.name.lower()

        if filename == "poetry.lock":
            return self._parse_poetry_lock(lockfile_path)
        if filename == "pipfile.lock":
            return self._parse_pipfile_lock(lockfile_path)
        if filename in {"conda-lock.yml", "conda-lock.yaml"}:
            return self._parse_conda_lock(lockfile_path)
        if filename in {"requirements.txt", "requirements-dev.txt"}:
            # Treat fully pinned requirements as a lock (best-effort)
            return self._parse_requirements_as_lock(lockfile_path)

        raise ValueError(f"Unsupported Python lockfile: {filename}")

    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Best-effort transitive resolution using PyPI JSON requires_dist.

        If version is not pinned, attempts latest metadata.
        Depth is limited to avoid excessive API calls.
        """
        all_deps = dependencies.copy()
        seen = {d.package.purl for d in dependencies}

        async with httpx.AsyncClient() as client:
            for dep in dependencies:
                nested = await self._resolve_pypi_requires_dist(client, dep.package, seen, depth=1, max_depth=2)
                all_deps.extend(nested)
        return all_deps

    # ----------------------
    # Parsers (manifests)
    # ----------------------
    def _parse_requirements(self, path: Path) -> List[Dependency]:
        deps: List[Dependency] = []
        try:
            content = path.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            return deps
        except Exception:
            return deps
            
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-r "):
                continue
            name, version = self._parse_requirement_line(line)
            if not name:
                continue
            pkg = self.create_package(name=name, version=version or "latest")
            deps.append(self.create_dependency(pkg, dependency_type=DependencyType.DIRECT, scope="runtime"))
        return deps

    def _parse_pyproject(self, path: Path) -> List[Dependency]:
        if toml is None:
            return []
        data = toml.loads(path.read_text(encoding="utf-8"))
        deps: List[Dependency] = []

        # Poetry-style
        tool_poetry = data.get("tool", {}).get("poetry", {})
        for section, dep_type in (("dependencies", DependencyType.DIRECT), ("dev-dependencies", DependencyType.DEV)):
            entries = tool_poetry.get(section, {})
            for name, spec in entries.items():
                if name.lower() in {"python"}:
                    continue
                version = self._extract_poetry_version(spec)
                pkg = self.create_package(name=name, version=version or "latest")
                deps.append(self.create_dependency(pkg, dependency_type=dep_type, scope="runtime" if dep_type==DependencyType.DIRECT else "development"))

        return deps

    def _parse_pipfile_manifest(self, path: Path) -> List[Dependency]:
        # Pipfile is TOML format
        if toml is None:
            return []
        data = toml.loads(path.read_text(encoding="utf-8"))
        deps: List[Dependency] = []
        for section, dep_type in (("packages", DependencyType.DIRECT), ("dev-packages", DependencyType.DEV)):
            entries = data.get(section, {})
            for name, spec in entries.items():
                version = self._extract_pip_like_version(spec)
                pkg = self.create_package(name=name, version=version or "latest")
                deps.append(self.create_dependency(pkg, dependency_type=dep_type, scope="runtime" if dep_type==DependencyType.DIRECT else "development"))
        return deps

    def _parse_conda_environment(self, path: Path) -> List[Dependency]:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        deps: List[Dependency] = []
        for item in data.get("dependencies", []) or []:
            if isinstance(item, str):
                # e.g., "numpy=1.24.0"
                if "=" in item:
                    name, version = item.split("=", 1)
                else:
                    name, version = item, "latest"
                pkg = self.create_package(name=name, version=version)
                deps.append(self.create_dependency(pkg, dependency_type=DependencyType.DIRECT, scope="runtime"))
            elif isinstance(item, dict) and "pip" in item:
                for req in item["pip"]:
                    n, v = self._parse_requirement_line(req)
                    if n:
                        pkg = self.create_package(name=n, version=v or "latest")
                        deps.append(self.create_dependency(pkg, dependency_type=DependencyType.DIRECT, scope="runtime"))
        return deps

    # ----------------------
    # Parsers (lockfiles)
    # ----------------------
    def _parse_poetry_lock(self, path: Path) -> List[Dependency]:
        if toml is None:
            return []
        data = toml.loads(path.read_text(encoding="utf-8"))
        pkgs = data.get("package", [])  # [[package]] array of tables
        deps: List[Dependency] = []
        for p in pkgs:
            name = p.get("name")
            version = p.get("version", "latest")
            if not name:
                continue
            pkg = self.create_package(name=name, version=version)
            deps.append(self.create_dependency(pkg, dependency_type=DependencyType.TRANSITIVE))
        return deps

    def _parse_pipfile_lock(self, path: Path) -> List[Dependency]:
        data = json.loads(path.read_text(encoding="utf-8"))
        deps: List[Dependency] = []
        for section in ("default", "develop"):
            entries: Dict[str, Any] = data.get(section, {})
            for name, meta in entries.items():
                ver = meta.get("version") or meta.get("ref") or "latest"
                if isinstance(ver, str) and ver.startswith("=="):
                    ver = ver[2:]
                pkg = self.create_package(name=name, version=ver)
                deps.append(self.create_dependency(pkg, dependency_type=DependencyType.TRANSITIVE))
        return deps

    def _parse_conda_lock(self, path: Path) -> List[Dependency]:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        deps: List[Dependency] = []
        # conda-lock schema contains a top-level "package" list
        for p in data.get("package", []) or []:
            name = p.get("name")
            version = p.get("version", "latest")
            if name:
                pkg = self.create_package(name=name, version=version)
                deps.append(self.create_dependency(pkg, dependency_type=DependencyType.TRANSITIVE))
        return deps

    def _parse_requirements_as_lock(self, path: Path) -> List[Dependency]:
        deps: List[Dependency] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-r "):
                continue
            name, version = self._parse_requirement_line(line)
            if not name:
                continue
            pkg = self.create_package(name=name, version=version or "latest")
            deps.append(self.create_dependency(pkg, dependency_type=DependencyType.TRANSITIVE))
        return deps

    # ----------------------
    # Helpers
    # ----------------------
    def _parse_requirement_line(self, line: str) -> tuple[Optional[str], Optional[str]]:
        # Remove environment markers
        line = line.split(";")[0].strip()
        # Remove extras
        line = re.sub(r"\[.*?\]", "", line)
        # VCS/URL requirements are treated as latest
        if line.startswith(("git+", "http://", "https://")):
            name = line.split("#egg=")[-1] if "#egg=" in line else None
            return name, "latest" if name else (None, None)

        # Order matters to avoid substring collisions
        operators = ["===", "==", ">=", "<=", "~=", "!=", ">", "<", "="]
        for op in operators:
            if op in line:
                parts = line.split(op, 1)
                name = parts[0].strip()
                version = parts[1].strip()
                if version.startswith("="):
                    version = version.lstrip("=")
                return name or None, version or None

        # No version specified
        return line.strip() or None, None

    def _extract_poetry_version(self, spec: Any) -> Optional[str]:
        if isinstance(spec, str):
            return spec.strip()
        if isinstance(spec, dict):
            return spec.get("version") or spec.get("rev") or None
        return None

    def _extract_pip_like_version(self, spec: Any) -> Optional[str]:
        if isinstance(spec, str):
            # Pipfile versions often look like "*" or "==1.2.3"
            s = spec.strip()
            if s.startswith("=="):
                return s[2:]
            if s == "*":
                return None
            return s
        if isinstance(spec, dict):
            # e.g., {version = "*"} or {ref="..."}
            v = spec.get("version") or spec.get("ref")
            if isinstance(v, str) and v.startswith("=="):
                return v[2:]
            return v
        return None

    async def _resolve_pypi_requires_dist(self, client: httpx.AsyncClient, package: Package, seen: set, depth: int, max_depth: int = 2) -> List[Dependency]:
        if depth > max_depth:
            return []
        deps: List[Dependency] = []
        name = package.name
        version = package.version if package.version and package.version != "latest" else "json"

        try:
            if version == "json":
                url = f"{self.pypi_api_json}/{name}/json"
            else:
                url = f"{self.pypi_api_json}/{name}/{package.version}/json"
            resp = await client.get(url, timeout=10.0)
            if resp.status_code != 200:
                return []
            data = resp.json()
            info = data.get("info", {})
            requires: List[str] = info.get("requires_dist") or []
            for req in requires:
                child_name, child_version = self._parse_requirement_line(req)
                if not child_name:
                    continue
                child_pkg = self.create_package(name=child_name, version=child_version or "latest")
                if child_pkg.purl in seen:
                    continue
                seen.add(child_pkg.purl)
                dep = self.create_dependency(package=child_pkg, dependency_type=DependencyType.TRANSITIVE, parent=package.purl, depth=depth)
                deps.append(dep)
                nested = await self._resolve_pypi_requires_dist(client, child_pkg, seen, depth+1, max_depth)
                deps.extend(nested)
        except Exception:
            return []

        return deps
