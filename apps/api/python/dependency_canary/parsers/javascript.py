"""
JavaScript/TypeScript parser for npm, yarn, and pnpm package managers.
"""

import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx
import asyncio
from ..models import Package, Dependency, DependencyType
from ..detectors import Language, PackageManager
from .base import BaseParser

class JavaScriptParser(BaseParser):
    """Parser for JavaScript/TypeScript projects."""
    
    def __init__(self, package_manager: PackageManager = PackageManager.NPM):
        """Initialize JavaScript parser.
        
        Args:
            package_manager: Package manager type (NPM, YARN, or PNPM)
        """
        super().__init__(Language.JAVASCRIPT, package_manager)
        self.registry_url = "https://registry.npmjs.org"
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse package.json file.
        
        Args:
            manifest_path: Path to package.json
            
        Returns:
            List of direct dependencies
        """
        try:
            content = self._read_file(manifest_path)
            package_json = json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError) as e:
            return []
        except Exception:
            return []
        
        dependencies = []
        
        # Parse production dependencies
        if "dependencies" in package_json:
            for name, version in package_json["dependencies"].items():
                package = self.create_package(
                    name=name,
                    version=self._parse_version_constraint(version),
                    namespace=self._extract_namespace(name)
                )
                dependency = self.create_dependency(
                    package=package,
                    dependency_type=DependencyType.DIRECT,
                    scope="runtime"
                )
                dependencies.append(dependency)
        
        # Parse development dependencies
        if "devDependencies" in package_json:
            for name, version in package_json["devDependencies"].items():
                package = self.create_package(
                    name=name,
                    version=self._parse_version_constraint(version),
                    namespace=self._extract_namespace(name)
                )
                dependency = self.create_dependency(
                    package=package,
                    dependency_type=DependencyType.DEV,
                    scope="development"
                )
                dependencies.append(dependency)
        
        # Parse optional dependencies
        if "optionalDependencies" in package_json:
            for name, version in package_json["optionalDependencies"].items():
                package = self.create_package(
                    name=name,
                    version=self._parse_version_constraint(version),
                    namespace=self._extract_namespace(name)
                )
                dependency = self.create_dependency(
                    package=package,
                    dependency_type=DependencyType.OPTIONAL,
                    scope="optional",
                    is_optional=True
                )
                dependencies.append(dependency)
        
        return dependencies
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml).
        
        Args:
            lockfile_path: Path to lockfile
            
        Returns:
            List of all dependencies with exact versions
        """
        filename = lockfile_path.name
        
        # First get direct dependencies from manifest to properly classify lockfile dependencies
        manifest_path = lockfile_path.parent / "package.json"
        direct_deps = set()
        if manifest_path.exists():
            try:
                manifest_content = self._read_file(manifest_path)
                package_json = json.loads(manifest_content)
                if "dependencies" in package_json:
                    direct_deps.update(package_json["dependencies"].keys())
                if "devDependencies" in package_json:
                    direct_deps.update(package_json["devDependencies"].keys())
                if "optionalDependencies" in package_json:
                    direct_deps.update(package_json["optionalDependencies"].keys())
            except Exception:
                pass  # Continue without manifest info
        
        if filename == "package-lock.json":
            return await self._parse_npm_lockfile(lockfile_path)
        elif filename == "yarn.lock":
            return await self._parse_yarn_lockfile(lockfile_path, direct_deps)
        elif filename == "pnpm-lock.yaml":
            return await self._parse_pnpm_lockfile(lockfile_path, direct_deps)
        else:
            raise ValueError(f"Unsupported lockfile: {filename}")
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies by querying npm registry.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies including transitive ones
        """
        all_dependencies = dependencies.copy()
        seen_packages = {dep.package.purl for dep in dependencies}
        
        async with httpx.AsyncClient() as client:
            for dependency in dependencies:
                transitive_deps = await self._resolve_package_dependencies(
                    client, dependency.package, seen_packages, depth=1
                )
                all_dependencies.extend(transitive_deps)
        
        return all_dependencies
    
    async def _parse_npm_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse package-lock.json file.
        
        Args:
            lockfile_path: Path to package-lock.json
            
        Returns:
            List of all dependencies
        """
        content = self._read_file(lockfile_path)
        lockfile_data = json.loads(content)
        
        dependencies = []
        
        # Handle lockfile version 1 and 2+
        if "dependencies" in lockfile_data:
            dependencies.extend(self._parse_npm_dependencies_v1(lockfile_data["dependencies"]))
        
        if "packages" in lockfile_data:
            dependencies.extend(self._parse_npm_dependencies_v2(lockfile_data["packages"]))
        
        return dependencies
    
    def _parse_npm_dependencies_v1(self, deps: Dict[str, Any], parent: Optional[str] = None, depth: int = 0) -> List[Dependency]:
        """Parse npm lockfile v1 dependencies format.
        
        Args:
            deps: Dependencies dictionary
            parent: Parent package PURL
            depth: Dependency depth
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        for name, info in deps.items():
            version = info.get("version", "unknown")
            
            package = self.create_package(
                name=name,
                version=version,
                namespace=self._extract_namespace(name)
            )
            
            dependency_type = DependencyType.DIRECT if depth == 0 else DependencyType.TRANSITIVE
            dependency = self.create_dependency(
                package=package,
                dependency_type=dependency_type,
                parent=parent,
                depth=depth
            )
            dependencies.append(dependency)
            
            # Recursively parse nested dependencies
            if "dependencies" in info:
                nested_deps = self._parse_npm_dependencies_v1(
                    info["dependencies"], package.purl, depth + 1
                )
                dependencies.extend(nested_deps)
        
        return dependencies
    
    def _parse_npm_dependencies_v2(self, packages: Dict[str, Any]) -> List[Dependency]:
        """Parse npm lockfile v2+ packages format.
        
        Args:
            packages: Packages dictionary
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        for package_path, info in packages.items():
            if package_path == "":  # Root package
                continue
            
            # Extract package name from path
            name = package_path.split("node_modules/")[-1]
            version = info.get("version", "unknown")
            
            package = self.create_package(
                name=name,
                version=version,
                namespace=self._extract_namespace(name)
            )
            
            # Determine if this is a direct or transitive dependency
            depth = package_path.count("node_modules/") - 1
            dependency_type = DependencyType.DIRECT if depth == 0 else DependencyType.TRANSITIVE
            
            dependency = self.create_dependency(
                package=package,
                dependency_type=dependency_type,
                depth=depth,
                is_optional=info.get("optional", False)
            )
            dependencies.append(dependency)
        
        return dependencies
    
    async def _parse_yarn_lockfile(self, lockfile_path: Path, direct_deps: set = None) -> List[Dependency]:
        """Parse yarn.lock file.
        
        Args:
            lockfile_path: Path to yarn.lock
            
        Returns:
            List of all dependencies
        """
        content = self._read_file(lockfile_path)
        dependencies = []
        
        # Simple yarn.lock parser (yarn.lock has a custom format)
        current_package = None
        current_version = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line and not line.startswith('#'):
                if line.endswith(':') and '@' in line:
                    # Package declaration line
                    package_spec = line[:-1]
                    if ',' in package_spec:
                        package_spec = package_spec.split(',')[0].strip()
                    
                    if '@' in package_spec:
                        parts = package_spec.rsplit('@', 1)
                        current_package = parts[0].strip('"')
                        # Version constraint is in parts[1] but we'll get actual version from "version" field
                
                elif line.startswith('version ') and current_package:
                    current_version = line.split('version ')[1].strip('"')
                    
                    package = self.create_package(
                        name=current_package,
                        version=current_version,
                        namespace=self._extract_namespace(current_package)
                    )
                    
                    # Determine if this is a direct or transitive dependency
                    dep_type = DependencyType.DIRECT if direct_deps and current_package in direct_deps else DependencyType.TRANSITIVE
                    
                    dependency = self.create_dependency(
                        package=package,
                        dependency_type=dep_type
                    )
                    dependencies.append(dependency)
                    
                    current_package = None
                    current_version = None
        
        return dependencies
    
    async def _parse_pnpm_lockfile(self, lockfile_path: Path, direct_deps: set = None) -> List[Dependency]:
        """Parse pnpm-lock.yaml file.
        
        Args:
            lockfile_path: Path to pnpm-lock.yaml
            
        Returns:
            List of all dependencies
        """
        content = self._read_file(lockfile_path)
        lockfile_data = yaml.safe_load(content)
        
        dependencies = []
        
        # Parse packages section
        if "packages" in lockfile_data:
            for package_spec, info in lockfile_data["packages"].items():
                # Parse package spec (e.g., "/@types/node/16.11.7")
                if package_spec.startswith('/'):
                    parts = package_spec[1:].split('/')
                    if len(parts) >= 2:
                        name = '/'.join(parts[:-1])
                        version = parts[-1]
                    else:
                        continue
                else:
                    continue
                
                package = self.create_package(
                    name=name,
                    version=version,
                    namespace=self._extract_namespace(name)
                )
                
                # Determine if this is a direct or transitive dependency
                dep_type = DependencyType.DIRECT if direct_deps and name in direct_deps else DependencyType.TRANSITIVE
                
                dependency = self.create_dependency(
                    package=package,
                    dependency_type=dep_type
                )
                dependencies.append(dependency)
        
        return dependencies
    
    async def _resolve_package_dependencies(self, client: httpx.AsyncClient, package: Package, 
                                          seen_packages: set, depth: int, max_depth: int = 3) -> List[Dependency]:
        """Resolve dependencies for a single package by querying npm registry.
        
        Args:
            client: HTTP client
            package: Package to resolve dependencies for
            seen_packages: Set of already seen package PURLs
            depth: Current depth in dependency tree
            max_depth: Maximum depth to resolve
            
        Returns:
            List of transitive dependencies
        """
        if depth > max_depth:
            return []
        
        dependencies = []
        
        try:
            # Query npm registry for package info
            url = f"{self.registry_url}/{package.name}/{package.version}"
            response = await client.get(url, timeout=10.0)
            
            if response.status_code == 200:
                package_info = response.json()
                
                # Parse dependencies from package.json
                if "dependencies" in package_info:
                    for dep_name, dep_version in package_info["dependencies"].items():
                        dep_package = self.create_package(
                            name=dep_name,
                            version=self._parse_version_constraint(dep_version),
                            namespace=self._extract_namespace(dep_name)
                        )
                        
                        if dep_package.purl not in seen_packages:
                            seen_packages.add(dep_package.purl)
                            
                            dependency = self.create_dependency(
                                package=dep_package,
                                dependency_type=DependencyType.TRANSITIVE,
                                parent=package.purl,
                                depth=depth
                            )
                            dependencies.append(dependency)
                            
                            # Recursively resolve transitive dependencies
                            nested_deps = await self._resolve_package_dependencies(
                                client, dep_package, seen_packages, depth + 1, max_depth
                            )
                            dependencies.extend(nested_deps)
        
        except Exception:
            # Skip packages that can't be resolved
            pass
        
        return dependencies
    
    def _extract_namespace(self, package_name: str) -> Optional[str]:
        """Extract namespace from scoped package name.
        
        Args:
            package_name: Package name (e.g., "@types/node")
            
        Returns:
            Namespace if scoped package, None otherwise
        """
        if package_name.startswith('@'):
            parts = package_name.split('/')
            if len(parts) >= 2:
                return parts[0][1:]  # Remove @ prefix
        return None
