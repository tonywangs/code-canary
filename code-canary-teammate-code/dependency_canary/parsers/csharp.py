"""
C# manifest parser for NuGet projects.
"""

from pathlib import Path
import re
import xml.etree.ElementTree as ET
import json
from typing import List, Dict, Any
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class CSharpParser(BaseParser):
    """Parser for C# NuGet projects."""
    
    def __init__(self):
        """Initialize C# parser."""
        super().__init__(Language.CSHARP, PackageManager.NUGET)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a C# project file or packages.config file.
        
        Args:
            manifest_path: Path to .csproj, .vbproj, packages.config, or Directory.Build.props file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name.endswith(".csproj") or manifest_path.name.endswith(".vbproj"):
            return await self._parse_project_file(manifest_path)
        elif manifest_path.name == "packages.config":
            return await self._parse_packages_config(manifest_path)
        elif manifest_path.name == "Directory.Build.props":
            return await self._parse_directory_build_props(manifest_path)
        else:
            return []
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a packages.lock.json file.
        
        Args:
            lockfile_path: Path to packages.lock.json file
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name == "packages.lock.json":
            return await self._parse_packages_lock_json(lockfile_path)
        else:
            return []
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies.
        
        For proper resolution, NuGet would need to be invoked.
        This implementation returns the input dependencies as is.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        # A proper implementation would use:
        # dotnet list package --include-transitive
        # to get the full dependency graph
        return dependencies
    
    async def _parse_project_file(self, project_path: Path) -> List[Dependency]:
        """Parse a .csproj or .vbproj file.
        
        Args:
            project_path: Path to project file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(project_path)
            
            # Parse XML content
            root = ET.fromstring(content)
            
            # SDK-style project files (new format)
            # Look for PackageReference items
            package_refs = root.findall(".//PackageReference") or root.findall(".//{http://schemas.microsoft.com/developer/msbuild/2003}PackageReference")
            
            for ref in package_refs:
                name = ref.get("Include") or ""
                version = ref.get("Version") or ""
                
                # If Version attribute is not present, look for Version element
                if not version:
                    version_elem = ref.find("Version")
                    if version_elem is not None and version_elem.text:
                        version = version_elem.text
                
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
                    
            # Older format (packages.config references)
            if not package_refs:
                # Check if there's a packages.config file in the same directory
                packages_config = project_path.parent / "packages.config"
                if packages_config.exists():
                    return await self._parse_packages_config(packages_config)
                    
        except Exception as e:
            # Log error
            print(f"Error parsing project file {project_path}: {e}")
            
        return dependencies
    
    async def _parse_packages_config(self, config_path: Path) -> List[Dependency]:
        """Parse a packages.config file.
        
        Args:
            config_path: Path to packages.config file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(config_path)
            
            # Parse XML content
            root = ET.fromstring(content)
            
            # Get all package elements
            packages = root.findall(".//package")
            
            for package in packages:
                name = package.get("id") or ""
                version = package.get("version") or ""
                
                # Check if this is a development dependency
                dev_dependency = package.get("developmentDependency", "").lower() == "true"
                
                if name:
                    package_obj = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    dependency_type = DependencyType.DEV if dev_dependency else DependencyType.DIRECT
                    
                    dependencies.append(self.create_dependency(
                        package=package_obj,
                        dependency_type=dependency_type,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing packages.config file {config_path}: {e}")
            
        return dependencies
    
    async def _parse_directory_build_props(self, props_path: Path) -> List[Dependency]:
        """Parse a Directory.Build.props file.
        
        Args:
            props_path: Path to Directory.Build.props file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(props_path)
            
            # Parse XML content
            root = ET.fromstring(content)
            
            # Look for PackageReference items in ItemGroup
            package_refs = root.findall(".//PackageReference") or root.findall(".//{http://schemas.microsoft.com/developer/msbuild/2003}PackageReference")
            
            for ref in package_refs:
                name = ref.get("Include") or ""
                version = ref.get("Version") or ""
                
                # If Version attribute is not present, look for Version element
                if not version:
                    version_elem = ref.find("Version")
                    if version_elem is not None and version_elem.text:
                        version = version_elem.text
                
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
            print(f"Error parsing Directory.Build.props file {props_path}: {e}")
            
        return dependencies
    
    async def _parse_packages_lock_json(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a packages.lock.json file.
        
        Args:
            lockfile_path: Path to packages.lock.json file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(lockfile_path)
            data = json.loads(content)
            
            # Process dependencies
            deps = data.get("dependencies", {})
            for name, dep_info in deps.items():
                version = dep_info.get("resolved", "")
                
                # Check if this is a direct dependency
                is_direct = dep_info.get("type", "") == "Direct"
                
                if name:
                    package = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    dependency_type = DependencyType.DIRECT if is_direct else DependencyType.TRANSITIVE
                    
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=dependency_type,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing packages.lock.json file {lockfile_path}: {e}")
            
        return dependencies
