"""
Java manifest parser for Maven and Gradle projects.
"""

from pathlib import Path
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Any, Optional, Set
import json
import os
import asyncio

from .base import BaseParser
from ..detectors import Language, PackageManager
from ..models import Dependency, DependencyType, Package

class JavaParser(BaseParser):
    """Parser for Java Maven and Gradle projects."""
    
    def __init__(self, package_manager: PackageManager = PackageManager.MAVEN):
        """Initialize Java parser.
        
        Args:
            package_manager: Java package manager (Maven or Gradle)
        """
        super().__init__(Language.JAVA, package_manager)
    
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a Maven or Gradle manifest file.
        
        Args:
            manifest_path: Path to pom.xml or build.gradle file
            
        Returns:
            List of direct dependencies
        """
        if manifest_path.name == "pom.xml":
            return await self._parse_maven_pom(manifest_path)
        elif manifest_path.name in ("build.gradle", "build.gradle.kts"):
            return await self._parse_gradle_build(manifest_path)
        else:
            return []
    
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a Maven or Gradle lockfile.
        
        Args:
            lockfile_path: Path to lockfile
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        if lockfile_path.name == "gradle.lockfile":
            return await self._parse_gradle_lockfile(lockfile_path)
        # Maven doesn't have a standard lockfile
        return []
    
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies for given direct dependencies.
        
        Note: For proper transitive resolution, an external tool like Maven or Gradle would be needed.
        This implementation returns the input dependencies as is.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies including transitive ones
        """
        # For proper transitive dependency resolution, we'd need to:
        # 1. Call Maven or Gradle command line to generate dependency tree
        # 2. Parse the output to build the dependency graph
        # This simplified implementation just returns the direct dependencies
        return dependencies
    
    async def _parse_maven_pom(self, pom_path: Path) -> List[Dependency]:
        """Parse Maven POM file.
        
        Args:
            pom_path: Path to pom.xml file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(pom_path)
            root = ET.fromstring(content)
            
            # Handle XML namespaces in POM files
            ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
            
            # Parse project coordinates
            project_group = root.findtext("maven:groupId", default="", namespaces=ns)
            project_artifact = root.findtext("maven:artifactId", default="", namespaces=ns)
            project_version = root.findtext("maven:version", default="", namespaces=ns)
            
            # Parse dependencies
            deps_element = root.find("maven:dependencies", namespaces=ns)
            if deps_element is not None:
                for dep in deps_element.findall("maven:dependency", namespaces=ns):
                    group_id = dep.findtext("maven:groupId", default="", namespaces=ns)
                    artifact_id = dep.findtext("maven:artifactId", default="", namespaces=ns)
                    version = dep.findtext("maven:version", default="", namespaces=ns)
                    scope = dep.findtext("maven:scope", default="compile", namespaces=ns)
                    
                    if artifact_id and group_id:
                        package = self.create_package(
                            name=f"{group_id}:{artifact_id}",
                            version=version or "unknown",
                            description="",
                            homepage="",
                            repository_url=""
                        )
                        
                        # Determine if this is a development dependency
                        dep_type = DependencyType.DEV if scope in ("test", "provided") else DependencyType.DIRECT
                        
                        dependencies.append(self.create_dependency(
                            package=package,
                            dependency_type=dep_type,
                            constraint=version or ""
                        ))
            
        except Exception as e:
            # Log error and return empty list
            print(f"Error parsing Maven POM {pom_path}: {e}")
        
        return dependencies
    
    async def _parse_gradle_build(self, gradle_path: Path) -> List[Dependency]:
        """Parse Gradle build file.
        
        Args:
            gradle_path: Path to build.gradle file
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(gradle_path)
            
            # Simple regex-based parsing of Gradle dependencies
            # This is a simplified approach - for robust parsing, we would need a proper Gradle parser
            dep_pattern = r"(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly)\s*['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
            
            for match in re.finditer(dep_pattern, content):
                config, group, artifact, version = match.groups()
                
                package = self.create_package(
                    name=f"{group}:{artifact}",
                    version=version,
                    description="",
                    homepage="",
                    repository_url=""
                )
                
                # Determine if this is a development dependency
                dep_type = DependencyType.DEV if config.startswith("test") else DependencyType.DIRECT
                
                dependencies.append(self.create_dependency(
                    package=package,
                    dependency_type=dep_type,
                    constraint=version
                ))
                
        except Exception as e:
            # Log error and return empty list
            print(f"Error parsing Gradle build file {gradle_path}: {e}")
        
        return dependencies
    
    async def _parse_gradle_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse Gradle lockfile.
        
        Args:
            lockfile_path: Path to gradle.lockfile
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            content = self._read_file(lockfile_path)
            
            # Gradle lockfiles typically look like:
            # org.example:library:1.0.0=...
            lock_pattern = r"([^:]+):([^:]+):([^=]+)="
            
            for line in content.splitlines():
                match = re.match(lock_pattern, line)
                if match:
                    group, artifact, version = match.groups()
                    
                    package = self.create_package(
                        name=f"{group}:{artifact}",
                        version=version.strip(),
                        description="",
                        homepage="",
                        repository_url=""
                    )
                    
                    # Lockfiles contain both direct and transitive dependencies
                    # Without additional information, we can't determine which are direct
                    dependencies.append(self.create_dependency(
                        package=package,
                        dependency_type=DependencyType.TRANSITIVE,  # Conservative assumption
                        constraint=version.strip()
                    ))
                    
        except Exception as e:
            # Log error and return empty list
            print(f"Error parsing Gradle lockfile {lockfile_path}: {e}")
        
        return dependencies
