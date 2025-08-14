"""
Command-line interface for Code Canary.
"""

import asyncio
import json
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from loguru import logger

from .sbom import SBOMGenerator
from .vulnerability import VulnerabilityEnricher
from .modal_workers import ModalSBOMService
from .models import ScanResult

console = Console()

@click.group()
@click.version_option(version="0.1.0")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def cli(verbose: bool):
    """Code Canary - SBOM & Vulnerability Enrichment"""
    if verbose:
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.add(sys.stderr, level="INFO")

@cli.command()
@click.argument("project_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file path")
@click.option("--format", "-f", type=click.Choice(["json", "yaml", "summary"]), 
              default="summary", help="Output format")
@click.option("--include-transitive/--no-transitive", default=True, 
              help="Include transitive dependencies")
@click.option("--remote", is_flag=True, help="Use Modal remote workers")
@click.option("--supply-chain", is_flag=True, help="Include supply chain intelligence analysis")
def scan(project_path: Path, output: Optional[Path], format: str, 
         include_transitive: bool, remote: bool, supply_chain: bool):
    """Scan a project directory for dependencies and vulnerabilities."""
    
    async def run_scan():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning project...", total=None)
            
            if remote:
                # Use Modal remote workers
                modal_service = ModalSBOMService()
                result = await modal_service.full_scan_remote(
                    project_path=project_path,
                    project_name=project_path.name
                )
            else:
                # Use local processing
                generator = SBOMGenerator()
                enricher = VulnerabilityEnricher()
                
                sbom = await generator.generate_sbom(
                    project_path=project_path,
                    project_name=project_path.name,
                    include_transitive=include_transitive
                )
                
                result = await enricher.enrich_sbom(sbom)
            
            # Add supply chain intelligence if requested
            if supply_chain:
                console.print("🔍 Gathering supply chain intelligence...")
                if remote:
                    modal_service = ModalSBOMService()
                    intelligence_data = await modal_service.gather_supply_chain_intelligence_remote(result.sbom.packages)
                else:
                    from .supply_chain_intelligence import SupplyChainIntelligence
                    intel_service = SupplyChainIntelligence()
                    intelligence_data = await intel_service.gather_package_intelligence(result.sbom.packages)
                    
                    # Convert to same format as Modal output
                    formatted_data = []
                    for intel in intelligence_data:
                        risk = intel_service.calculate_supply_chain_risk(intel)
                        formatted_data.append({
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
                        })
                    intelligence_data = formatted_data
                
                # Add intelligence data to result for output
                result.supply_chain_intelligence = intelligence_data
         
        # Output results in the requested format
        if format == "json":
            class DateTimeEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    elif isinstance(obj, Enum):
                        return obj.value
                    elif isinstance(obj, set):
                        return list(obj)
                    return super().default(obj)
                    
            output_data = json.dumps(result.model_dump(), indent=2, cls=DateTimeEncoder)
        elif format == "yaml":
            import yaml
            output_data = yaml.dump(result.model_dump(), default_flow_style=False)
        else:
            output_data = _format_summary(result)
        
        if output:
            output.write_text(output_data)
            console.print(f"✅ Results saved to {output}")
        else:
            console.print(output_data)
    
    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("❌ Scan cancelled")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Scan failed: {e}")
        sys.exit(1)

@cli.command()
@click.argument("project_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file path")
@click.option("--format", "-f", type=click.Choice(["json", "yaml"]), 
              default="json", help="Output format")
def sbom(project_path: Path, output: Optional[Path], format: str):
    """Generate SBOM (Software Bill of Materials) for a project."""
    
    async def generate_sbom():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Generating SBOM...", total=None)
            
            generator = SBOMGenerator()
            sbom_result = await generator.generate_sbom(
                project_path=project_path,
                project_name=project_path.name,
                include_transitive=True
            )
         
        # Output SBOM
        if format == "json":
            class DateTimeEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    elif isinstance(obj, Enum):
                        return obj.value
                    elif isinstance(obj, set):
                        return list(obj)
                    return super().default(obj)
                    
            output_data = json.dumps(sbom_result.model_dump(), indent=2, cls=DateTimeEncoder)
        else:
            import yaml
            output_data = yaml.dump(sbom_result.model_dump(), default_flow_style=False)
        
        if output:
            output.write_text(output_data)
            console.print(f"✅ SBOM saved to {output}")
        else:
            console.print(output_data)
    
    try:
        asyncio.run(generate_sbom())
    except Exception as e:
        console.print(f"❌ SBOM generation failed: {e}")
        sys.exit(1)

@cli.command()
@click.argument("project_path", type=click.Path(exists=True, path_type=Path))
def detect(project_path: Path):
    """Detect package managers and manifest files in a project."""
    
    from .detectors import LanguageDetector
    
    detector = LanguageDetector()
    manifests = detector.detect_manifests(project_path)
    
    if not manifests:
        console.print("❌ No supported manifest files found")
        return
    
    # Create table of detected manifests
    table = Table(title="Detected Manifest Files")
    table.add_column("File", style="cyan")
    table.add_column("Language", style="green")
    table.add_column("Package Manager", style="blue")
    table.add_column("Type", style="yellow")
    table.add_column("Priority", style="red")
    
    for manifest in manifests:
        table.add_row(
            str(manifest.path.relative_to(project_path)),
            manifest.language.value,
            manifest.package_manager.value,
            manifest.manifest_type,
            str(manifest.priority)
        )
    
    console.print(table)
    
    # Show language summary
    languages = detector.get_project_languages(project_path)
    package_managers = detector.get_package_managers(project_path)
    
    console.print(f"\n📊 **Summary:**")
    console.print(f"Languages: {', '.join([lang.value for lang in languages])}")
    console.print(f"Package Managers: {', '.join([pm.value for pms in package_managers.values() for pm in pms])}")

def _format_summary(result: ScanResult) -> str:
    """Format scan result as a summary."""
    
    # Create summary panel
    summary_content = f"""
 📦 **Project:** {result.sbom.project_name}
 📊 **Total Packages:** {result.sbom.total_packages}
 🔗 **Direct Dependencies:** {result.sbom.direct_dependencies}
 🌐 **Transitive Dependencies:** {result.sbom.transitive_dependencies}
 🔍 **Languages:** {', '.join(result.sbom.languages)}
 📋 **Package Managers:** {', '.join(result.sbom.package_managers)}

 🚨 **Vulnerabilities:**
   • Critical: {result.critical_vulnerabilities}
   • High: {result.high_vulnerabilities}
   • Medium: {result.medium_vulnerabilities}
   • Low: {result.low_vulnerabilities}
   • Total: {result.total_vulnerabilities}
"""
    
    if result.scan_duration_seconds:
        summary_content += f"\n⏱️ **Scan Duration:** {result.scan_duration_seconds:.2f} seconds"
    
    return summary_content.strip()

if __name__ == "__main__":
    cli()
