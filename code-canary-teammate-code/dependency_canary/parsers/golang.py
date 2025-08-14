"""
Go manifest parser for Go Modules projects.
"""

from pathlib import Path
import re
from typing import List, Dict, Any, Set
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class GoParser(BaseParser):
    """Parser for Go modules projects."""
    
    def __init__(self):
        """Initialize Go parser."""
        super().__init__(Language.GO, PackageManager.GO_MODULES)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a go.mod file.
        
        Args:
            manifest_path: Path to go.mod file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name != "go.mod":
            return []
            
        dependencies = []
        
        try:
            content = self._read_file(manifest_path)
            
            # Extract module name (first line usually)
            module_name = ""
            module_match = re.search(r"module\s+(.+)", content)
            if module_match:
                module_name = module_match.group(1).strip()
            
            # Extract Go version
            go_version = "unknown"
            go_match = re.search(r"go\s+([0-9.]+)", content)
            if go_match:
                go_version = go_match.group(1).strip()
            
            # Extract require statements
            # Single-line requires (exclude block syntax)
            require_pattern = r"^require\s+([^\s\(\)]+)\s+([^\s\(\)]+)$"
            for line in content.splitlines():
                line = line.strip()
                match = re.match(require_pattern, line)
                if match:
                    pkg_name, version = match.groups()
                    
                    # Clean up version (remove 'v' prefix if present)
                    version = version.strip()
                    
                    package = self.create_package(
                        name=pkg_name.strip(),
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
            
            # Multi-line require block
            require_blocks = re.findall(r"require\s*\(\s*([\s\S]*?)\s*\)", content)
            for block in require_blocks:
                for line in block.strip().split("\n"):
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name, version = parts[0], parts[1]
                        
                        package = self.create_package(
                            name=pkg_name.strip(),
                            version=version.strip(),
                            description="",
                            homepage="",
                            repository_url=""
                        )
                        
                        dependencies.append(self.create_dependency(
                            package=package,
                            dependency_type=DependencyType.DIRECT,
                            constraint=version.strip()
                        ))
                        
        except Exception as e:
            # Log error
            print(f"Error parsing Go module file {manifest_path}: {e}")
            
        return dependencies
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a go.sum lockfile.
        
        Args:
            lockfile_path: Path to go.sum file
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name != "go.sum":
            return []
            
        dependencies = []
        package_versions = set()  # To avoid duplicates
        
        try:
            content = self._read_file(lockfile_path)
            
            # Format: github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
            # or: github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
            pattern = r"^([^\s]+)\s+([^\s/]+)(?:/go\.mod)?\s+"
            
            for line in content.splitlines():
                match = re.match(pattern, line)
                if match:
                    pkg_name, version = match.groups()
                    
                    # Avoid duplicates (go.sum has multiple entries per package)
                    pkg_key = f"{pkg_name}@{version}"
                    if pkg_key in package_versions:
                        continue
                    
                    package_versions.add(pkg_key)
                    
                    package = self.create_package(
                        name=pkg_name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    dependencies.append(self.create_dependency(
                        package=package,
                        # go.sum contains both direct and transitive dependencies
                        # Without additional info, we assume transitive to be conservative
                        dependency_type=DependencyType.TRANSITIVE,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing go.sum file {lockfile_path}: {e}")
            
        return dependencies
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies.
        
        For proper resolution, we would need to use 'go mod graph' command.
        This implementation assumes that lockfile parsing will capture all dependencies.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        # A proper implementation would use:
        # go mod graph | awk '{if ($1 !~ "@") print $0}' | sort | uniq
        # to get the full dependency graph
        return dependencies
