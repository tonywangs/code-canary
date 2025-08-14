"""
Ruby manifest parser for Bundler projects.
"""

from pathlib import Path
import re
import yaml
from typing import List, Dict, Any
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class RubyParser(BaseParser):
    """Parser for Ruby Bundler projects."""
    
    def __init__(self):
        """Initialize Ruby parser."""
        super().__init__(Language.RUBY, PackageManager.BUNDLER)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a Gemfile file.
        
        Args:
            manifest_path: Path to Gemfile file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name != "Gemfile":
            return []
            
        dependencies = []
        
        try:
            content = self._read_file(manifest_path)
            
            # Parse gem lines
            # This is a simplified regex that may not catch all valid Gemfile formats
            # For robust parsing, a proper Ruby parser would be needed
            gem_pattern = r'gem\s+[\'"]([^\'"]+)[\'"](?:\s*,\s*[\'"]([^\'"]+)[\'"])?'
            group_pattern = r'group\s+:(\w+)(?:\s*,\s*:(\w+))*\s+do(.*?)end'
            
            # Process regular gem lines
            for match in re.finditer(gem_pattern, content):
                name = match.group(1)
                version = match.group(2) or ""
                
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
            
            # Process grouped gems (e.g., development, test)
            for group_match in re.finditer(group_pattern, content, re.DOTALL):
                group_names = [g for g in group_match.groups()[:-1] if g]
                group_content = group_match.group(len(group_match.groups()))
                
                # Check if this is a development/test group
                is_dev_group = any(g in ["development", "test"] for g in group_names)
                
                # Find gems in this group
                for gem_match in re.finditer(gem_pattern, group_content):
                    name = gem_match.group(1)
                    version = gem_match.group(2) or ""
                    
                    package = self.create_package(
                        name=name,
                        version=version,
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    # Use DEV dependency type for gems in development or test groups
                    dep_type = DependencyType.DEV if is_dev_group else DependencyType.DIRECT
                    
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=dep_type,
                        constraint=version
                    ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing Gemfile {manifest_path}: {e}")
            
        return dependencies
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a Gemfile.lock lockfile.
        
        Args:
            lockfile_path: Path to Gemfile.lock file
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name != "Gemfile.lock":
            return []
            
        dependencies = []
        
        try:
            content = self._read_file(lockfile_path)
            
            # Gemfile.lock has a specific format with GEM, PLATFORMS, and DEPENDENCIES sections
            # Here we'll parse the "GEM" section to get all gems with versions
            
            # Find the GEM section
            gem_section_match = re.search(r"GEM\n(.*?)(?:\n\n|\Z)", content, re.DOTALL)
            if gem_section_match:
                gem_section = gem_section_match.group(1)
                
                # Parse specs
                specs_match = re.search(r"  specs:\n(.*?)(?:\n\n|\Z)", gem_section, re.DOTALL)
                if specs_match:
                    specs = specs_match.group(1)
                    
                    # Each line with two spaces followed by name and version is a dependency
                    for line in specs.split("\n"):
                        # Match lines that look like "    name (version)"
                        dep_match = re.match(r'    ([^ ]+) \(([^)]+)\)', line)
                        if dep_match:
                            name = dep_match.group(1)
                            version = dep_match.group(2)
                            
                            package = self.create_package(
                                name=name,
                                version=version,
                                description="",
                                homepage="",
                                repository_url=""
                            )
                            
                            # We can't easily distinguish direct vs transitive in Gemfile.lock
                            # without parsing the DEPENDENCIES section and checking against it
                            dependencies.append(self.create_dependency(
                                package=package,
                                dependency_type=DependencyType.TRANSITIVE,  # Conservative assumption
                                constraint=version
                            ))
                    
        except Exception as e:
            # Log error
            print(f"Error parsing Gemfile.lock {lockfile_path}: {e}")
            
        return dependencies
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies.
        
        For proper resolution, Bundler would need to be invoked.
        This implementation returns the input dependencies as is.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        # A proper implementation would use:
        # bundle list --without-groups development test
        # to get all dependencies
        return dependencies
