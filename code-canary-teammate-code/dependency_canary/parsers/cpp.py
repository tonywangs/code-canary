"""
C/C++ manifest parser for vcpkg and conan projects.
"""

from pathlib import Path
import json
import re
from typing import List, Dict, Any
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class CppParser(BaseParser):
    """Parser for C/C++ projects using vcpkg or conan."""
    
    def __init__(self, package_manager: PackageManager = PackageManager.VCPKG):
        """Initialize C/C++ parser.
        
        Args:
            package_manager: C/C++ package manager (vcpkg or conan)
        """
        super().__init__(Language.CPP, package_manager)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a vcpkg.json or conanfile.txt file.
        
        Args:
            manifest_path: Path to manifest file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name == "vcpkg.json":
            return await self._parse_vcpkg_json(manifest_path)
        elif manifest_path.name == "conanfile.txt":
            return await self._parse_conanfile_txt(manifest_path)
        elif manifest_path.name == "conanfile.py":
            return await self._parse_conanfile_py(manifest_path)
        else:
            return []
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a lockfile.
        
        Args:
            lockfile_path: Path to lockfile
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name == "vcpkg-configuration.json":
            return await self._parse_vcpkg_configuration(lockfile_path)
        elif lockfile_path.name == "conan.lock":
            return await self._parse_conan_lock(lockfile_path)
        else:
            return []
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies.
        
        For proper resolution, vcpkg or conan would need to be invoked.
        This implementation returns the input dependencies as is.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        # A proper implementation would use:
        # vcpkg list or conan info
        # to get the full dependency graph
        return dependencies
    
    async def _parse_vcpkg_json(self, manifest_path: Path) -> List[Dependency]:
        """Parse a vcpkg.json file.
        
        Args:
            manifest_path: Path to vcpkg.json file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(manifest_path)
            data = json.loads(content)
            
            # Extract package metadata
            package_name = data.get("name", "")
            package_version = data.get("version", "")
            
            # Process dependencies
            deps = data.get("dependencies", [])
            for dep in deps:
                if isinstance(dep, str):
                    # Simple dependency "name"
                    name = dep
                    version = ""
                elif isinstance(dep, dict):
                    # Complex dependency {"name": "libname", "version>=": "1.0.0"}
                    name = dep.get("name", "")
                    # Combine all version constraints
                    version = ""
                    for key, value in dep.items():
                        if "version" in key and key != "name":
                            version += f"{key.replace('version', '')}{value} "
                    version = version.strip()
                else:
                    continue
                
                if name:
                    package = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=DependencyType.DIRECT,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing vcpkg.json file {manifest_path}: {e}")
            
        return dependencies
    
    async def _parse_conanfile_txt(self, manifest_path: Path) -> List[Dependency]:
        """Parse a conanfile.txt file.
        
        Args:
            manifest_path: Path to conanfile.txt file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(manifest_path)
            
            # Find [requires] section
            requires_match = re.search(r"\[requires\](.*?)(?:\[|\Z)", content, re.DOTALL)
            if requires_match:
                requires_section = requires_match.group(1)
                
                # Process each requirement line
                for line in requires_section.strip().split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                        
                    # Parse requirement (e.g., "zlib/1.2.11")
                    parts = line.split("/")
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].split("@")[0] if "@" in parts[1] else parts[1]
                        
                        package = self.create_package(
                            name=name,
                            version=version,
                            description="",
                            homepage="",
                            repository_url=""
                        )
                        
                        dependencies.append(self.create_dependency(
                            package=package,
                            dependency_type=DependencyType.DIRECT,
                            constraint=version
                        ))
                        
        except Exception as e:
            # Log error
            print(f"Error parsing conanfile.txt {manifest_path}: {e}")
            
        return dependencies
    
    async def _parse_conanfile_py(self, manifest_path: Path) -> List[Dependency]:
        """Parse a conanfile.py file.
        
        Note: Proper parsing would require Python AST parsing or execution.
        This implementation uses regex for basic extraction.
        
        Args:
            manifest_path: Path to conanfile.py file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(manifest_path)
            
            # Extract requires using regex
            # Look for requires = ["pkg1/version", "pkg2/version"]
            # or self.requires("pkg/version")
            requires_list_pattern = r'requires\s*=\s*\[(.*?)\]'
            requires_method_pattern = r'self\.requires\([\'"]([^\'"]+)[\'"]\)'
            
            # Process requires list
            requires_list_match = re.search(requires_list_pattern, content, re.DOTALL)
            if requires_list_match:
                requires_items = requires_list_match.group(1)
                # Extract items from the list
                item_pattern = r'[\'"]([^\'"]+)[\'"](,|$)'
                for match in re.finditer(item_pattern, requires_items):
                    requirement = match.group(1)
                    parts = requirement.split("/")
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].split("@")[0] if "@" in parts[1] else parts[1]
                        
                        package = self.create_package(
                            name=name,
                            version=version,
                            description="",
                            homepage="",
                            repository_url=""
                        )
                        
                        dependencies.append(self.create_dependency(
                            package=package,
                            dependency_type=DependencyType.DIRECT,
                            constraint=version
                        ))
            
            # Process requires method calls
            for match in re.finditer(requires_method_pattern, content):
                requirement = match.group(1)
                parts = requirement.split("/")
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].split("@")[0] if "@" in parts[1] else parts[1]
                    
                    package = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=DependencyType.DIRECT,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing conanfile.py {manifest_path}: {e}")
            
        return dependencies
    
    async def _parse_vcpkg_configuration(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a vcpkg-configuration.json file.
        
        Args:
            lockfile_path: Path to vcpkg-configuration.json
            
        Returns:
            List of dependencies
        """
        # vcpkg-configuration.json doesn't typically list all dependencies with versions
        # It contains registry information, so we return an empty list for now
        return []
    
    async def _parse_conan_lock(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a conan.lock file.
        
        Args:
            lockfile_path: Path to conan.lock file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(lockfile_path)
            data = json.loads(content)
            
            # Extract graph nodes from lock file
            nodes = data.get("graph_lock", {}).get("nodes", {})
            
            for node_id, node in nodes.items():
                # Skip the root node (usually node 0)
                if node_id == "0":
                    continue
                    
                # Get package reference
                ref = node.get("ref", "")
                if ref:
                    # Format is typically name/version@user/channel
                    parts = ref.split("/")
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].split("@")[0] if "@" in parts[1] else parts[1]
                        
                        package = self.create_package(
                            name=name,
                            version=version,
                            description="",
                            homepage="",
                            repository_url=""
                        )
                        
                        # Lockfiles contain both direct and transitive dependencies
                        dependencies.append(self.create_dependency(
                            package=package,
                            dependency_type=DependencyType.TRANSITIVE,  # Conservative assumption
                            constraint=version
                        ))
                        
        except Exception as e:
            # Log error
            print(f"Error parsing conan.lock file {lockfile_path}: {e}")
            
        return dependencies
