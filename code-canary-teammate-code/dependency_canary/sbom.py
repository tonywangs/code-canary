"""
SBOM (Software Bill of Materials) generator.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Optional
from loguru import logger

from .models import SBOM, Package, Dependency, ScanResult, DependencyType
from .detectors import LanguageDetector, DetectedManifest, Language, PackageManager
from .parsers import (
    BaseParser, JavaScriptParser, PythonParser, JavaParser, 
    GoParser, RustParser, RubyParser, CppParser, CSharpParser
)

class SBOMGenerator:
    """Generates Software Bill of Materials from project directories."""
    
    def __init__(self):
        """Initialize SBOM generator."""
        self.detector = LanguageDetector()
        self.parsers = self._initialize_parsers()
    
    def _initialize_parsers(self) -> Dict[PackageManager, BaseParser]:
        """Initialize parsers for different package managers.
        
        Returns:
            Dictionary mapping package managers to their parsers
        """
        return {
            # JavaScript/TypeScript parsers
            PackageManager.NPM: JavaScriptParser(PackageManager.NPM),
            PackageManager.YARN: JavaScriptParser(PackageManager.YARN),
            PackageManager.PNPM: JavaScriptParser(PackageManager.PNPM),
            
            # Python parsers
            PackageManager.PIP: PythonParser(PackageManager.PIP),
            PackageManager.POETRY: PythonParser(PackageManager.POETRY),
            PackageManager.PIPENV: PythonParser(PackageManager.PIPENV),
            PackageManager.CONDA: PythonParser(PackageManager.CONDA),
            
            # Java parsers
            PackageManager.MAVEN: JavaParser(PackageManager.MAVEN),
            PackageManager.GRADLE: JavaParser(PackageManager.GRADLE),
            
            # Go parser
            PackageManager.GO_MODULES: GoParser(),
            
            # Rust parser
            PackageManager.CARGO: RustParser(),
            
            # Ruby parser
            PackageManager.BUNDLER: RubyParser(),
            
            # C/C++ parsers
            PackageManager.VCPKG: CppParser(PackageManager.VCPKG),
            PackageManager.CONAN: CppParser(PackageManager.CONAN),
            
            # C# parser
            PackageManager.NUGET: CSharpParser(),
        }
    
    async def generate_sbom(self, project_path: Path, 
                          project_name: Optional[str] = None,
                          include_transitive: bool = True) -> SBOM:
        """Generate SBOM for a project directory.
        
        Args:
            project_path: Path to project directory
            project_name: Optional project name
            include_transitive: Whether to include transitive dependencies
            
        Returns:
            Generated SBOM
        """
        logger.info(f"Generating SBOM for project: {project_path}")
        
        # Detect manifests in the project
        manifests = self.detector.detect_manifests(project_path)
        logger.info(f"Detected {len(manifests)} manifest files")
        
        if not manifests:
            logger.warning("No supported manifest files found")
            return SBOM(
                project_name=project_name or project_path.name,
                project_path=str(project_path)
            )
        
        # Initialize SBOM
        sbom = SBOM(
            project_name=project_name or project_path.name,
            project_path=str(project_path)
        )
        
        # Parse manifests in parallel
        parse_tasks = []
        for manifest in manifests:
            if manifest.package_manager in self.parsers:
                task = self._parse_manifest(manifest, include_transitive)
                parse_tasks.append(task)
            else:
                logger.warning(f"No parser available for {manifest.package_manager}")
        
        # Execute parsing tasks
        if parse_tasks:
            results = await asyncio.gather(*parse_tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to parse manifest {manifests[i].path}: {result}")
                    continue
                
                dependencies = result
                for dependency in dependencies:
                    sbom.add_package(dependency.package, dependency)
        
        logger.info(f"Generated SBOM with {sbom.total_packages} packages")
        return sbom
    
    async def _parse_manifest(self, manifest: DetectedManifest, 
                            include_transitive: bool) -> List[Dependency]:
        """Parse a single manifest file.
        
        Args:
            manifest: Detected manifest information
            include_transitive: Whether to include transitive dependencies
            
        Returns:
            List of dependencies
        """
        parser = self.parsers[manifest.package_manager]
        dependencies = []
        
        try:
            if manifest.manifest_type == "lockfile":
                # Parse lockfile for exact versions
                dependencies = await parser.parse_lockfile(manifest.path)
            else:
                # Parse manifest file
                dependencies = await parser.parse_manifest(manifest.path)
                
                # Resolve transitive dependencies if requested
                if include_transitive:
                    # Look for corresponding lockfile first
                    lockfile_path = self._find_lockfile(manifest)
                    if lockfile_path and lockfile_path.exists():
                        # Use lockfile for complete dependency tree
                        lockfile_deps = await parser.parse_lockfile(lockfile_path)
                        dependencies.extend(lockfile_deps)
                    else:
                        # Resolve transitive dependencies via API
                        transitive_deps = await parser.resolve_transitive_dependencies(dependencies)
                        dependencies = transitive_deps
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {manifest.path}")
            
        except Exception as e:
            logger.error(f"Failed to parse {manifest.path}: {e}")
            raise
        
        return dependencies
    
    def _find_lockfile(self, manifest: DetectedManifest) -> Optional[Path]:
        """Find corresponding lockfile for a manifest.
        
        Args:
            manifest: Detected manifest
            
        Returns:
            Path to lockfile if found
        """
        manifest_dir = manifest.path.parent
        
        # Mapping of package managers to their lockfiles
        lockfile_names = {
            PackageManager.NPM: ["package-lock.json"],
            PackageManager.YARN: ["yarn.lock"],
            PackageManager.PNPM: ["pnpm-lock.yaml"],
            PackageManager.PIP: ["requirements.lock", "pip.lock"],
            PackageManager.POETRY: ["poetry.lock"],
            PackageManager.PIPENV: ["Pipfile.lock"],
            PackageManager.CONDA: ["conda-lock.yml", "conda-lock.yaml"],
            PackageManager.MAVEN: ["maven.lock"],
            PackageManager.GRADLE: ["gradle.lockfile"],
            PackageManager.GO_MODULES: ["go.sum"],
            PackageManager.CARGO: ["Cargo.lock"],
            PackageManager.BUNDLER: ["Gemfile.lock"],
        }
        
        if manifest.package_manager in lockfile_names:
            for lockfile_name in lockfile_names[manifest.package_manager]:
                lockfile_path = manifest_dir / lockfile_name
                if lockfile_path.exists():
                    return lockfile_path
        
        return None
    
    async def generate_sbom_from_container(self, container_image: str) -> SBOM:
        """Generate SBOM from a container image using Syft JSON output.
        Requires `syft` to be installed and available on PATH.
        """
        logger.info(f"Generating container SBOM for image: {container_image}")
        sbom = SBOM(project_name=container_image, project_path=container_image)

        try:
            proc = await asyncio.create_subprocess_exec(
                "syft", container_image, "-o", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error(f"Syft failed for {container_image}: {stderr.decode().strip()}")
                return sbom

            data = json.loads(stdout.decode() or "{}")
            artifacts = data.get("artifacts", [])

            count = 0
            for art in artifacts:
                name = (art.get("name") or "").strip()
                version = (art.get("version") or "").strip()
                if not name or not version:
                    continue

                language = (art.get("language") or "unknown").lower()
                pkg_type = (art.get("type") or "unknown").lower()

                package = Package(
                    name=name,
                    version=version,
                    language=language,
                    package_manager=pkg_type,
                )
                dependency = Dependency(
                    package=package,
                    dependency_type=DependencyType.DIRECT,
                    scope="runtime",
                    depth=0,
                )
                sbom.add_package(package, dependency)
                count += 1

            logger.info(f"Container SBOM generated with {count} packages for {container_image}")
            return sbom
        except FileNotFoundError:
            logger.error("Syft not found. Install from https://github.com/anchore/syft")
            return sbom
        except Exception as e:
            logger.error(f"Failed to generate container SBOM for {container_image}: {e}")
            return sbom
    
    def get_supported_languages(self) -> List[Language]:
        """Get list of supported programming languages.
        
        Returns:
            List of supported Language enums
        """
        from .detectors import Language
        return [
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.GO,
            Language.JAVA,
            Language.RUST,
            Language.RUBY,
            Language.CPP,
            Language.CSHARP
        ]
    
    def get_supported_package_managers(self) -> List[PackageManager]:
        """Get list of supported package managers.
        
        Returns:
            List of supported PackageManager enums
        """
        from .detectors import PackageManager
        return [
            PackageManager.PIP,
            PackageManager.POETRY,
            PackageManager.PIPENV,
            PackageManager.CONDA,
            PackageManager.NPM,
            PackageManager.YARN,
            PackageManager.PNPM,
            PackageManager.GO_MODULES,
            PackageManager.MAVEN,
            PackageManager.GRADLE,
            PackageManager.CARGO,
            PackageManager.BUNDLER
        ]

class ParallelSBOMGenerator(SBOMGenerator):
    """SBOM generator optimized for parallel processing with Modal."""
    
    def __init__(self, max_workers: int = 10):
        """Initialize parallel SBOM generator.
        
        Args:
            max_workers: Maximum number of parallel workers
        """
        super().__init__()
        self.max_workers = max_workers
    
    async def generate_sbom_parallel(self, project_paths: List[Path]) -> List[SBOM]:
        """Generate SBOMs for multiple projects in parallel.
        
        Args:
            project_paths: List of project directories
            
        Returns:
            List of generated SBOMs
        """
        logger.info(f"Generating SBOMs for {len(project_paths)} projects in parallel")
        
        # Create semaphore to limit concurrent operations
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def generate_with_semaphore(path: Path) -> SBOM:
            async with semaphore:
                return await self.generate_sbom(path)
        
        # Execute SBOM generation in parallel
        tasks = [generate_with_semaphore(path) for path in project_paths]
        sboms = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log errors
        valid_sboms = []
        for i, sbom in enumerate(sboms):
            if isinstance(sbom, Exception):
                logger.error(f"Failed to generate SBOM for {project_paths[i]}: {sbom}")
            else:
                valid_sboms.append(sbom)
        
        logger.info(f"Successfully generated {len(valid_sboms)} SBOMs")
        return valid_sboms

    def get_supported_languages(self) -> List[Language]:
        """Get list of supported languages.
        
        Returns:
            List of supported languages
        """
        languages = set()
        for parser in self.parsers.values():
            languages.add(parser.language)
        return list(languages)
    
    def get_supported_package_managers(self) -> List[PackageManager]:
        """Get list of supported package managers.
        
        Returns:
            List of supported package managers
        """
        return list(self.parsers.keys())
