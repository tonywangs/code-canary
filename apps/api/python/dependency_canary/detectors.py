"""
Language and package manager detection for dependency scanning.
"""

import os
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum

class Language(Enum):
    """Supported programming languages."""
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    RUBY = "ruby"
    CPP = "cpp"
    CSHARP = "csharp"

class PackageManager(Enum):
    """Supported package managers."""
    # JavaScript/TypeScript
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    
    # Python
    PIP = "pip"
    POETRY = "poetry"
    PIPENV = "pipenv"
    CONDA = "conda"
    
    # Java
    MAVEN = "maven"
    GRADLE = "gradle"
    
    # Go
    GO_MODULES = "go_modules"
    
    # Rust
    CARGO = "cargo"
    
    # Ruby
    BUNDLER = "bundler"
    
    # C/C++
    VCPKG = "vcpkg"
    CONAN = "conan"
    
    # C#
    NUGET = "nuget"

@dataclass
class DetectedManifest:
    """Represents a detected package manifest file."""
    path: Path
    language: Language
    package_manager: PackageManager
    manifest_type: str  # e.g., "manifest", "lockfile", "config"
    priority: int  # Higher number = higher priority for parsing

class LanguageDetector:
    """Detects programming languages and package managers in a project."""
    
    # Mapping of file patterns to language/package manager combinations
    MANIFEST_PATTERNS = {
        # JavaScript/TypeScript
        "package.json": (Language.JAVASCRIPT, PackageManager.NPM, "manifest", 10),
        "package-lock.json": (Language.JAVASCRIPT, PackageManager.NPM, "lockfile", 9),
        "yarn.lock": (Language.JAVASCRIPT, PackageManager.YARN, "lockfile", 9),
        "pnpm-lock.yaml": (Language.JAVASCRIPT, PackageManager.PNPM, "lockfile", 9),
        ".yarnrc.yml": (Language.JAVASCRIPT, PackageManager.YARN, "config", 5),
        ".npmrc": (Language.JAVASCRIPT, PackageManager.NPM, "config", 5),
        
        # Python
        "requirements.txt": (Language.PYTHON, PackageManager.PIP, "manifest", 8),
        "requirements-dev.txt": (Language.PYTHON, PackageManager.PIP, "manifest", 7),
        "requirements.in": (Language.PYTHON, PackageManager.PIP, "manifest", 7),
        "pyproject.toml": (Language.PYTHON, PackageManager.POETRY, "manifest", 10),
        "poetry.lock": (Language.PYTHON, PackageManager.POETRY, "lockfile", 9),
        "Pipfile": (Language.PYTHON, PackageManager.PIPENV, "manifest", 8),
        "Pipfile.lock": (Language.PYTHON, PackageManager.PIPENV, "lockfile", 9),
        "environment.yml": (Language.PYTHON, PackageManager.CONDA, "manifest", 8),
        "environment.yaml": (Language.PYTHON, PackageManager.CONDA, "manifest", 8),
        "conda-lock.yml": (Language.PYTHON, PackageManager.CONDA, "lockfile", 9),
        "setup.py": (Language.PYTHON, PackageManager.PIP, "manifest", 6),
        "setup.cfg": (Language.PYTHON, PackageManager.PIP, "config", 5),
        
        # Java
        "pom.xml": (Language.JAVA, PackageManager.MAVEN, "manifest", 10),
        "build.gradle": (Language.JAVA, PackageManager.GRADLE, "manifest", 10),
        "build.gradle.kts": (Language.JAVA, PackageManager.GRADLE, "manifest", 10),
        "gradle.lockfile": (Language.JAVA, PackageManager.GRADLE, "lockfile", 9),
        "settings.gradle": (Language.JAVA, PackageManager.GRADLE, "config", 5),
        
        # Go
        "go.mod": (Language.GO, PackageManager.GO_MODULES, "manifest", 10),
        "go.sum": (Language.GO, PackageManager.GO_MODULES, "lockfile", 9),
        
        # Rust
        "Cargo.toml": (Language.RUST, PackageManager.CARGO, "manifest", 10),
        "Cargo.lock": (Language.RUST, PackageManager.CARGO, "lockfile", 9),
        
        # Ruby
        "Gemfile": (Language.RUBY, PackageManager.BUNDLER, "manifest", 10),
        "Gemfile.lock": (Language.RUBY, PackageManager.BUNDLER, "lockfile", 9),
        "gems.rb": (Language.RUBY, PackageManager.BUNDLER, "manifest", 8),
        "gems.locked": (Language.RUBY, PackageManager.BUNDLER, "lockfile", 8),
        
        # C/C++
        "vcpkg.json": (Language.CPP, PackageManager.VCPKG, "manifest", 10),
        "conanfile.txt": (Language.CPP, PackageManager.CONAN, "manifest", 9),
        "conanfile.py": (Language.CPP, PackageManager.CONAN, "manifest", 10),
        "conan.lock": (Language.CPP, PackageManager.CONAN, "lockfile", 9),
        
        # C#
        "packages.config": (Language.CSHARP, PackageManager.NUGET, "manifest", 8),
        "*.csproj": (Language.CSHARP, PackageManager.NUGET, "manifest", 9),
        "*.fsproj": (Language.CSHARP, PackageManager.NUGET, "manifest", 9),
        "*.vbproj": (Language.CSHARP, PackageManager.NUGET, "manifest", 9),
        "paket.dependencies": (Language.CSHARP, PackageManager.NUGET, "manifest", 8),
        "paket.lock": (Language.CSHARP, PackageManager.NUGET, "lockfile", 8),
    }
    
    def __init__(self, max_depth: int = 10):
        """Initialize the language detector.
        
        Args:
            max_depth: Maximum directory depth to search
        """
        self.max_depth = max_depth
    
    def detect_manifests(self, root_path: Path) -> List[DetectedManifest]:
        """Detect all package manifests in a directory tree.
        
        Args:
            root_path: Root directory to search
            
        Returns:
            List of detected manifest files
        """
        manifests = []
        
        for file_path in self._walk_directory(root_path):
            manifest = self._check_file(file_path)
            if manifest:
                manifests.append(manifest)
        
        # Sort by priority (highest first) and then by path
        manifests.sort(key=lambda m: (-m.priority, str(m.path)))
        
        return manifests
    
    def get_project_languages(self, root_path: Path) -> Set[Language]:
        """Get all detected languages in a project.
        
        Args:
            root_path: Root directory to analyze
            
        Returns:
            Set of detected languages
        """
        manifests = self.detect_manifests(root_path)
        return {manifest.language for manifest in manifests}
    
    def get_package_managers(self, root_path: Path) -> Dict[Language, List[PackageManager]]:
        """Get package managers grouped by language.
        
        Args:
            root_path: Root directory to analyze
            
        Returns:
            Dictionary mapping languages to their package managers
        """
        manifests = self.detect_manifests(root_path)
        result = {}
        
        for manifest in manifests:
            if manifest.language not in result:
                result[manifest.language] = []
            
            if manifest.package_manager not in result[manifest.language]:
                result[manifest.language].append(manifest.package_manager)
        
        return result
    
    def _walk_directory(self, root_path: Path) -> List[Path]:
        """Walk directory tree and return all files up to max_depth.
        
        Args:
            root_path: Root directory to walk
            
        Returns:
            List of file paths
        """
        files = []
        
        def _walk(path: Path, depth: int):
            if depth > self.max_depth:
                return
            
            try:
                for item in path.iterdir():
                    if item.is_file():
                        files.append(item)
                    elif item.is_dir() and not self._should_skip_directory(item):
                        _walk(item, depth + 1)
            except (PermissionError, OSError):
                # Skip directories we can't read
                pass
        
        _walk(root_path, 0)
        return files
    
    def _should_skip_directory(self, path: Path) -> bool:
        """Check if a directory should be skipped during traversal.
        
        Args:
            path: Directory path to check
            
        Returns:
            True if directory should be skipped
        """
        skip_dirs = {
            '.git', '.svn', '.hg',  # Version control
            'node_modules', '__pycache__', '.pytest_cache',  # Build artifacts
            'target', 'build', 'dist', 'out',  # Build directories
            '.idea', '.vscode', '.vs',  # IDE directories
            'venv', '.venv', 'env', '.env',  # Virtual environments
        }
        
        return path.name in skip_dirs or path.name.startswith('.')
    
    def _check_file(self, file_path: Path) -> DetectedManifest | None:
        """Check if a file matches any known manifest patterns.
        
        Args:
            file_path: File path to check
            
        Returns:
            DetectedManifest if file matches a pattern, None otherwise
        """
        filename = file_path.name
        
        # Check exact filename matches
        if filename in self.MANIFEST_PATTERNS:
            lang, pm, mtype, priority = self.MANIFEST_PATTERNS[filename]
            return DetectedManifest(file_path, lang, pm, mtype, priority)
        
        # Check pattern matches (e.g., *.csproj)
        for pattern, (lang, pm, mtype, priority) in self.MANIFEST_PATTERNS.items():
            if '*' in pattern:
                if self._matches_pattern(filename, pattern):
                    return DetectedManifest(file_path, lang, pm, mtype, priority)
        
        return None
    
    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches a glob-like pattern.
        
        Args:
            filename: Filename to check
            pattern: Pattern to match against
            
        Returns:
            True if filename matches pattern
        """
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
