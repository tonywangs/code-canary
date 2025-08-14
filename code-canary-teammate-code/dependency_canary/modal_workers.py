"""
Modal workers for parallel SBOM generation and vulnerability enrichment.
"""

import modal
import asyncio
from pathlib import Path
from typing import List, Dict, Any
import os
from loguru import logger

from .sbom import SBOMGenerator
from .vulnerability import VulnerabilityEnricher
from .supply_chain_intelligence import SupplyChainIntelligence
from .models import SBOM, ScanResult, Package

# Create Modal app
app = modal.App("renamed-project")

# Define the container image with all dependencies
image = (
    modal.Image.debian_slim()
    .apt_install(["curl", "ca-certificates"])
    .run_commands([
        "bash -lc 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin'",
    ])
    .pip_install([
        "httpx>=0.25.0",
        "pydantic>=2.0.0",
        "loguru>=0.7.0",
        "toml>=0.10.2",
        "PyYAML>=6.0",
        "networkx>=3.0",  # For dependency graph analysis
    ])
)

# Shared volume for temporary file storage
volume = modal.Volume.from_name("renamed-project-data", create_if_missing=True)

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=300,
    memory=1024,
    cpu=2.0
)
async def generate_sbom_worker(project_data: Dict[str, Any]) -> Dict[str, Any]:
    """Modal worker function to generate SBOM for a single project.
    
    Args:
        project_data: Dictionary containing project information
        
    Returns:
        Serialized SBOM data
    """
    try:
        project_path = Path(project_data["path"])
        project_name = project_data.get("name")
        include_transitive = project_data.get("include_transitive", True)
        
        logger.info(f"Generating SBOM for {project_path}")
        
        generator = SBOMGenerator()
        sbom = await generator.generate_sbom(
            project_path=project_path,
            project_name=project_name,
            include_transitive=include_transitive
        )
        
        # Serialize SBOM to dictionary
        return sbom.model_dump()
        
    except Exception as e:
        logger.error(f"Failed to generate SBOM: {e}")
        raise

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=600,
    memory=2048,
    cpu=4.0,
    max_containers=10
)
async def enrich_vulnerabilities_worker(sbom_data: Dict[str, Any]) -> Dict[str, Any]:
    """Modal worker function to enrich SBOM with vulnerability data.
    
    Args:
        sbom_data: Serialized SBOM data
        
    Returns:
        Enriched scan result with vulnerabilities
    """
    try:
        # Deserialize SBOM
        sbom = SBOM.model_validate(sbom_data)
        
        logger.info(f"Enriching vulnerabilities for {sbom.total_packages} packages")
        
        # Initialize vulnerability enricher
        enricher = VulnerabilityEnricher()
        
        # Enrich with vulnerability data
        scan_result = await enricher.enrich_sbom(sbom)
        
        # Serialize scan result
        return scan_result.model_dump()
        
    except Exception as e:
        logger.error(f"Failed to enrich vulnerabilities: {e}")
        raise

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=120,
    memory=512,
    cpu=1.0
)
async def detect_manifests_worker(project_path: str) -> List[Dict[str, Any]]:
    """Modal worker function to detect manifest files in a project.
    
    Args:
        project_path: Path to project directory
        
    Returns:
        List of detected manifest information
    """
    try:
        from .detectors import LanguageDetector
        
        detector = LanguageDetector()
        manifests = detector.detect_manifests(Path(project_path))
        
        # Serialize manifest data
        return [
            {
                "path": str(manifest.path),
                "language": manifest.language.value,
                "package_manager": manifest.package_manager.value,
                "manifest_type": manifest.manifest_type,
                "priority": manifest.priority
            }
            for manifest in manifests
        ]
        
    except Exception as e:
        logger.error(f"Failed to detect manifests: {e}")
        raise

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=1800,  # 30 minutes
    memory=4096,
    cpu=8.0
)
async def full_scan_worker(project_data: Dict[str, Any]) -> Dict[str, Any]:
    """Modal worker function to perform complete security scan.
    
    Args:
        project_data: Dictionary containing project information
        
    Returns:
        Complete scan result with SBOM, vulnerabilities, and risk analysis
    """
    try:
        import time
        start_time = time.time()
        
        project_path = Path(project_data["path"])
        project_name = project_data.get("name")
        
        logger.info(f"Starting full security scan for {project_path}")
        
        # Step 1: Generate SBOM
        generator = SBOMGenerator()
        sbom = await generator.generate_sbom(
            project_path=project_path,
            project_name=project_name,
            include_transitive=True
        )
        
        logger.info(f"Generated SBOM with {sbom.total_packages} packages")
        
        # Step 2: Enrich with vulnerabilities
        enricher = VulnerabilityEnricher()
        scan_result = await enricher.enrich_sbom(sbom)
        
        logger.info(f"Found {scan_result.total_vulnerabilities} vulnerabilities")
        
        # Step 3: Perform risk analysis (placeholder for future enhancements)
        
        # Calculate scan duration
        scan_result.scan_duration_seconds = time.time() - start_time
        
        logger.info(f"Completed full scan in {scan_result.scan_duration_seconds:.2f} seconds")
        
        return scan_result.model_dump()
        
    except Exception as e:
        logger.error(f"Failed to perform full scan: {e}")
        raise

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=900,
    memory=2048,
    cpu=2.0
)
async def generate_image_sbom_worker(image_ref: str) -> Dict[str, Any]:
    """Generate SBOM for a container image using Syft inside the worker image."""
    try:
        logger.info(f"Generating image SBOM for {image_ref}")
        generator = SBOMGenerator()
        sbom = await generator.generate_sbom_from_container(image_ref)
        return sbom.model_dump()
    except Exception as e:
        logger.error(f"Failed to generate image SBOM: {e}")
        raise

@app.function(
    image=image,
    volumes={"/data": volume},
    timeout=300,
    memory=1024,
    cpu=2.0,
    max_containers=20
)
async def supply_chain_intelligence_worker(packages_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Modal worker function to gather supply chain intelligence for packages.
    
    Args:
        packages_data: List of serialized Package data
        
    Returns:
        List of package intelligence and risk assessments
    """
    try:
        # Deserialize packages
        packages = [Package.model_validate(pkg_data) for pkg_data in packages_data]
        
        logger.info(f"Gathering supply chain intelligence for {len(packages)} packages")
        
        # Initialize intelligence service
        intel_service = SupplyChainIntelligence()
        
        # Gather intelligence
        intelligence_data = await intel_service.gather_package_intelligence(packages)
        
        # Calculate risks
        results = []
        for intel in intelligence_data:
            risk = intel_service.calculate_supply_chain_risk(intel)
            
            result = {
                "package_name": intel.package_name,
                "package_manager": intel.package_manager,
                "version": intel.version,
                "intelligence": {
                    "weekly_downloads": intel.weekly_downloads,
                    "total_downloads": intel.total_downloads,
                    "maintainers": intel.maintainers,
                    "upload_time": intel.upload_time.isoformat() if intel.upload_time else None,
                    "project_urls": intel.project_urls,
                    "dependencies_count": intel.dependencies_count,
                    "is_very_new": intel.is_very_new,
                    "low_download_count": intel.low_download_count,
                    "suspicious_name": intel.suspicious_name,
                    "potential_typosquat": intel.potential_typosquat,
                },
                "supply_chain_risk": {
                    "risk_level": risk.risk_level,
                    "risk_score": risk.risk_score,
                    "risk_factors": risk.risk_factors,
                    "recommendations": risk.recommendations,
                }
            }
            results.append(result)
        
        logger.info(f"Completed supply chain intelligence analysis for {len(results)} packages")
        
        return results
        
    except Exception as e:
        logger.error(f"Failed to gather supply chain intelligence: {e}")
        raise

class ModalSBOMService:
    """Service class for interacting with Modal workers."""
    
    def __init__(self):
        """Initialize Modal SBOM service."""
        self.app = app
    
    async def generate_sbom_remote(self, project_path: Path, 
                                 project_name: str = None) -> SBOM:
        """Generate SBOM using Modal worker.
        
        Args:
            project_path: Path to project directory
            project_name: Optional project name
            
        Returns:
            Generated SBOM
        """
        project_data = {
            "path": str(project_path),
            "name": project_name
        }
        
        try:
            sbom_data = await generate_sbom_worker.remote(project_data)
            return SBOM.model_validate(sbom_data)
        except Exception as e:
            logger.error(f"Remote SBOM generation failed: {e}")
            # Fall back to local processing
            logger.info("Falling back to local processing")
            generator = SBOMGenerator()
            return await generator.generate_sbom(project_path, project_name)
    
    async def enrich_vulnerabilities_remote(self, sbom: SBOM) -> ScanResult:
        """Enrich SBOM with vulnerabilities using Modal worker.
        
        Args:
            sbom: SBOM to enrich
            
        Returns:
            Enriched scan result
        """
        try:
            sbom_data = sbom.model_dump()
            result_data = await enrich_vulnerabilities_worker.remote(sbom_data)
            return ScanResult.model_validate(result_data)
        except Exception as e:
            logger.error(f"Remote vulnerability enrichment failed: {e}")
            # Fall back to local processing
            logger.info("Falling back to local processing")
            enricher = VulnerabilityEnricher()
            return await enricher.enrich_sbom(sbom)
    
    async def full_scan_remote(self, project_path: Path, 
                             project_name: str = None) -> ScanResult:
        """Perform complete security scan using Modal worker.
        
        Args:
            project_path: Path to project directory
            project_name: Optional project name
            
        Returns:
            Complete scan result
        """
        project_data = {
            "path": str(project_path),
            "name": project_name
        }
        
        try:
            result_data = await full_scan_worker.remote(project_data)
            return ScanResult.model_validate(result_data)
        except Exception as e:
            logger.error(f"Remote scan failed: {e}")
            # Fall back to local processing
            logger.info("Falling back to local processing")
            sbom = await self.generate_sbom_remote(project_path, project_name)
            return await self.enrich_vulnerabilities_remote(sbom)
    
    async def generate_image_sbom_remote(self, image_ref: str) -> SBOM:
        """Generate SBOM for a container image using Modal.
        
        Args:
            image_ref: Container image reference (e.g., 'ubuntu:latest')
            
        Returns:
            Generated SBOM
        """
        try:
            sbom_data = await generate_image_sbom_worker.remote(image_ref)
            return SBOM.model_validate(sbom_data)
        except Exception as e:
            logger.error(f"Remote container image scan failed: {e}")
            # Fall back to local processing if possible
            logger.info("Falling back to local processing")
            generator = SBOMGenerator()
            return await generator.generate_sbom_from_container(image_ref)
    
    async def gather_supply_chain_intelligence_remote(self, packages: List[Package]) -> List[Dict[str, Any]]:
        """Gather supply chain intelligence using Modal worker.
        
        Args:
            packages: List of packages to analyze
            
        Returns:
            List of intelligence and risk data
        """
        try:
            # Serialize packages for Modal worker
            packages_data = [pkg.model_dump() for pkg in packages]
            
            # Process in batches of 50 to avoid overwhelming APIs
            batch_size = 50
            all_results = []
            
            for i in range(0, len(packages_data), batch_size):
                batch = packages_data[i:i + batch_size]
                batch_results = await supply_chain_intelligence_worker.remote(batch)
                all_results.extend(batch_results)
            
            return all_results
            
        except Exception as e:
            logger.error(f"Remote supply chain intelligence gathering failed: {e}")
            # Fall back to local processing
            logger.info("Falling back to local processing")
            intel_service = SupplyChainIntelligence()
            intelligence_data = await intel_service.gather_package_intelligence(packages)
            
            results = []
            for intel in intelligence_data:
                risk = intel_service.calculate_supply_chain_risk(intel)
                result = {
                    "package_name": intel.package_name,
                    "package_manager": intel.package_manager,
                    "version": intel.version,
                    "intelligence": {
                        "weekly_downloads": intel.weekly_downloads,
                        "total_downloads": intel.total_downloads,
                        "maintainers": intel.maintainers,
                        "upload_time": intel.upload_time.isoformat() if intel.upload_time else None,
                        "project_urls": intel.project_urls,
                        "dependencies_count": intel.dependencies_count,
                        "is_very_new": intel.is_very_new,
                        "low_download_count": intel.low_download_count,
                        "suspicious_name": intel.suspicious_name,
                        "potential_typosquat": intel.potential_typosquat,
                    },
                    "supply_chain_risk": {
                        "risk_level": risk.risk_level,
                        "risk_score": risk.risk_score,
                        "risk_factors": risk.risk_factors,
                        "recommendations": risk.recommendations,
                    }
                }
                results.append(result)
            
            return results

# CLI function for Modal deployment
@app.local_entrypoint()
def main(project_path: str = ".", output_format: str = "json"):
    """CLI entrypoint for Modal deployment.
    
    Args:
        project_path: Path to project directory to scan
        output_format: Output format (json, yaml, or summary)
    """
    import asyncio
    import json
    
    async def run_scan():
        service = ModalSBOMService()
        result = await service.full_scan_remote(Path(project_path))
        
        if output_format == "json":
            from datetime import datetime
            from enum import Enum
            
            class DateTimeEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    elif isinstance(obj, Enum):
                        return obj.value
                    elif isinstance(obj, set):
                        return list(obj)
                    return super().default(obj)
            
            print(json.dumps(result.model_dump(), indent=2, cls=DateTimeEncoder))
        elif output_format == "summary":
            print(f"Scan Results for {result.sbom.project_name}")
            print(f"Total packages: {result.sbom.total_packages}")
            print(f"Vulnerabilities: {result.total_vulnerabilities}")
            print(f"Critical: {result.critical_vulnerabilities}")
            print(f"High: {result.high_vulnerabilities}")
            print(f"Medium: {result.medium_vulnerabilities}")
            print(f"Low: {result.low_vulnerabilities}")
        
        return result
    
    return asyncio.run(run_scan())
