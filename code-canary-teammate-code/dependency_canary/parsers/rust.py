"""
Rust manifest parser for Cargo projects.
"""

from pathlib import Path
import toml
from typing import List, Dict, Any
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class RustParser(BaseParser):
    """Parser for Rust Cargo projects."""
    
    def __init__(self):
        """Initialize Rust parser."""
        super().__init__(Language.RUST, PackageManager.CARGO)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a Cargo.toml file.
        
        Args:
            manifest_path: Path to Cargo.toml file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name != "Cargo.toml":
            return []
            
        dependencies = []
        
        try:
            # Parse TOML file
            data = toml.loads(self._read_file(manifest_path))
            
            # Extract package metadata
            package_name = data.get("package", {}).get("name", "")
            package_version = data.get("package", {}).get("version", "0.0.0")
            package_description = data.get("package", {}).get("description", "")
            
            # Process dependencies section
            deps = data.get("dependencies", {})
            for name, constraint in deps.items():
                # Handle different dependency specification formats
                version = ""
                if isinstance(constraint, str):
                    version = constraint
                elif isinstance(constraint, dict):
                    version = constraint.get("version", "")
                    # Handle git dependencies
                    if "git" in constraint and not version:
                        version = f"git:{constraint['git']}"
                    # Handle path dependencies
                    elif "path" in constraint and not version:
                        version = f"path:{constraint['path']}"
                
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
            
            # Process dev-dependencies section
            dev_deps = data.get("dev-dependencies", {})
            for name, constraint in dev_deps.items():
                # Handle different dependency specification formats
                version = ""
                if isinstance(constraint, str):
                    version = constraint
                elif isinstance(constraint, dict):
                    version = constraint.get("version", "")
                    # Handle git dependencies
                    if "git" in constraint and not version:
                        version = f"git:{constraint['git']}"
                    # Handle path dependencies
                    elif "path" in constraint and not version:
                        version = f"path:{constraint['path']}"
                
                package = self.create_package(
                    name=name,
                    version=version,
                    description="",
                    homepage="",
                    repository_url=""
                )
                
                dependencies.append(self.create_dependency(
                    package=package,
                    dependency_type=DependencyType.DEV,
                    constraint=version
                ))
            
            # Handle workspace dependencies if present
            workspace_deps = {}
            if "workspace" in data and "dependencies" in data["workspace"]:
                workspace_deps = data["workspace"]["dependencies"]
                
            for name, constraint in workspace_deps.items():
                # Handle different dependency specification formats
                version = ""
                if isinstance(constraint, str):
                    version = constraint
                elif isinstance(constraint, dict):
                    version = constraint.get("version", "")
                
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
            print(f"Error parsing Cargo.toml file {manifest_path}: {e}")
            
        return dependencies
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a Cargo.lock lockfile.
        
        Args:
            lockfile_path: Path to Cargo.lock file
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name != "Cargo.lock":
            return []
            
        dependencies = []
        
        try:
            # Parse TOML file
            data = toml.loads(self._read_file(lockfile_path))
            
            # Process packages
            # Cargo.lock has a list of packages in TOML format
            packages = data.get("package", [])
            
            for package_info in packages:
                name = package_info.get("name", "")
                version = package_info.get("version", "")
                
                if name and version:
                    package = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    # Lockfiles contain all dependencies (direct and transitive)
                    # Without additional info, we assume transitive to be conservative
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=DependencyType.TRANSITIVE,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing Cargo.lock file {lockfile_path}: {e}")
            
        return dependencies
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies.
        
        For proper resolution, we would need to use 'cargo metadata'.
        This implementation assumes that lockfile parsing will capture all dependencies.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        # A proper implementation would use:
        # cargo metadata --format-version=1
        # to get the full dependency graph
        return dependencies
