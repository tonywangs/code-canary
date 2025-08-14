"""
Base parser class for manifest file parsing.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Dict, Any
from ..models import Package, Dependency, DependencyType
from ..detectors import Language, PackageManager

class BaseParser(ABC):
    """Abstract base class for manifest parsers."""
    
    def __init__(self, language: Language, package_manager: PackageManager):
        """Initialize parser with language and package manager.
        
        Args:
            language: Programming language
            package_manager: Package manager type
        """
        self.language = language
        self.package_manager = package_manager
    
    @abstractmethod
    async def parse_manifest(self, manifest_path: Path) -> List[Dependency]:
        """Parse a manifest file and return dependencies.
        
        Args:
            manifest_path: Path to manifest file
            
        Returns:
            List of direct dependencies
        """
        pass
    
    @abstractmethod
    async def parse_lockfile(self, lockfile_path: Path) -> List[Dependency]:
        """Parse a lockfile and return all dependencies with exact versions.
        
        Args:
            lockfile_path: Path to lockfile
            
        Returns:
            List of all dependencies (direct and transitive)
        """
        pass
    
    @abstractmethod
    async def resolve_transitive_dependencies(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Resolve transitive dependencies for given direct dependencies.
        
        Args:
            dependencies: List of direct dependencies
            
        Returns:
            List of all dependencies including transitive ones
        """
        pass
    
    def create_package(self, name: str, version: str, **kwargs) -> Package:
        """Create a Package instance with common fields.
        
        Args:
            name: Package name
            version: Package version
            **kwargs: Additional package metadata
            
        Returns:
            Package instance
        """
        return Package(
            name=name,
            version=version,
            language=self.language.value,
            package_manager=self.package_manager.value,
            **kwargs
        )
    
    def create_dependency(self, package: Package, dependency_type: DependencyType = DependencyType.DIRECT, **kwargs) -> Dependency:
        """Create a Dependency instance.
        
        Args:
            package: Package instance
            dependency_type: Type of dependency
            **kwargs: Additional dependency metadata
            
        Returns:
            Dependency instance
        """
        return Dependency(
            package=package,
            dependency_type=dependency_type,
            **kwargs
        )
    
    def _read_file(self, file_path: Path) -> str:
        """Read file contents safely.
        
        Args:
            file_path: Path to file
            
        Returns:
            File contents as string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file can't be read
        """
        try:
            return file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in ['latin-1', 'cp1252']:
                try:
                    return file_path.read_text(encoding=encoding)
                except UnicodeDecodeError:
                    continue
            raise IOError(f"Could not decode file {file_path}")
    
    def _normalize_version(self, version: str) -> str:
        """Normalize version string by removing prefixes and suffixes.
        
        Args:
            version: Raw version string
            
        Returns:
            Normalized version string
        """
        # Remove common prefixes
        version = version.lstrip('^~>=<!')
        
        # Remove git commit hashes and URLs
        if version.startswith('git+') or '#' in version:
            return "latest"
        
        # Handle version ranges (take the minimum version)
        if ' - ' in version:
            version = version.split(' - ')[0]
        
        return version.strip()
    
    def _parse_version_constraint(self, constraint: str) -> str:
        """Parse version constraint and extract the actual version.
        
        Args:
            constraint: Version constraint string (e.g., "^1.2.3", ">=2.0.0")
            
        Returns:
            Extracted version string
        """
        # Handle npm-style constraints
        if constraint.startswith('^'):
            return constraint[1:]
        elif constraint.startswith('~'):
            return constraint[1:]
        elif constraint.startswith('>='):
            return constraint[2:]
        elif constraint.startswith('>'):
            return constraint[1:]
        elif constraint.startswith('<='):
            return constraint[2:]
        elif constraint.startswith('<'):
            return constraint[1:]
        elif constraint.startswith('='):
            return constraint[1:]
        
        return constraint
    
    async def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if parser can handle this file
        """
        return file_path.exists() and file_path.is_file()
