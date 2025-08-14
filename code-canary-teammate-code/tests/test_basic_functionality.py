#!/usr/bin/env python3
"""
Basic functionality tests for Code Canary.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from dependency_canary.modal_workers import ModalSBOMService
from dependency_canary.sbom import SBOMGenerator
from dependency_canary.vulnerability import VulnerabilityEnricher
from dependency_canary.detectors import LanguageDetector
from dependency_canary.models import SBOM, Package, Dependency, DependencyType


class TestLanguageDetection:
    """Test language and manifest detection."""
    
    def test_detect_python_requirements(self):
        """Test detection of Python requirements.txt."""
        detector = LanguageDetector()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create a requirements.txt file
            (tmppath / "requirements.txt").write_text("requests==2.25.1\nnumpy>=1.20.0")
            
            manifests = detector.detect_manifests(tmppath)
            
            assert len(manifests) == 1
            assert manifests[0].language.value == "python"
            assert manifests[0].package_manager.value == "pip"
            assert manifests[0].path.name == "requirements.txt"
    
    def test_detect_javascript_package_json(self):
        """Test detection of JavaScript package.json."""
        detector = LanguageDetector()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create a package.json file
            (tmppath / "package.json").write_text('{"name": "test", "dependencies": {"lodash": "^4.17.21"}}')
            
            manifests = detector.detect_manifests(tmppath)
            
            assert len(manifests) == 1
            assert manifests[0].language.value == "javascript"
            assert manifests[0].package_manager.value == "npm"


class TestSBOMGeneration:
    """Test SBOM generation functionality."""
    
    @pytest.mark.asyncio
    async def test_generate_sbom_python_project(self):
        """Test SBOM generation for a Python project."""
        generator = SBOMGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create a simple requirements.txt
            (tmppath / "requirements.txt").write_text("requests==2.25.1\nclick==8.0.0")
            
            sbom = await generator.generate_sbom(
                project_path=tmppath,
                project_name="test-project"
            )
            
            assert sbom.project_name == "test-project"
            # With transitive dependencies enabled, we get more than just the 2 direct deps
            assert sbom.total_packages >= 2
            assert sbom.direct_dependencies == 2
            assert "python" in sbom.languages
            assert "pip" in sbom.package_managers
            
            # Check that we have the expected packages
            package_names = [pkg.name for pkg in sbom.packages]
            assert "requests" in package_names
            assert "click" in package_names
    
    @pytest.mark.asyncio
    async def test_empty_project(self):
        """Test SBOM generation for an empty project."""
        generator = SBOMGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            sbom = await generator.generate_sbom(
                project_path=tmppath,
                project_name="empty-project"
            )
            
            assert sbom.project_name == "empty-project"
            assert sbom.total_packages == 0
            assert len(sbom.packages) == 0


class TestVulnerabilityEnrichment:
    """Test vulnerability enrichment functionality."""
    
    @pytest.mark.asyncio
    async def test_enrich_empty_sbom(self):
        """Test enrichment of an empty SBOM."""
        enricher = VulnerabilityEnricher()
        
        sbom = SBOM(project_name="test", project_path="/test")
        result = await enricher.enrich_sbom(sbom)
        
        assert result.sbom == sbom
        assert result.total_vulnerabilities == 0
        assert len(result.risks) == 0
    
    @pytest.mark.asyncio
    async def test_enrich_sbom_with_mock_vulnerability(self):
        """Test enrichment with a mocked vulnerability response."""
        enricher = VulnerabilityEnricher()
        
        # Create SBOM with a test package
        sbom = SBOM(project_name="test", project_path="/test")
        test_package = Package(
            name="test-package",
            version="1.0.0",
            language="python",
            package_manager="pip"
        )
        sbom.packages.append(test_package)
        sbom.total_packages = 1
        
        # Mock the HTTP client to return no vulnerabilities
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulns": []}
            
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await enricher.enrich_sbom(sbom)
            
            assert result.sbom == sbom
            assert result.total_vulnerabilities == 0


class TestIntegration:
    """Test integration functionality."""
    
    @pytest.mark.asyncio
    async def test_basic_sbom_and_enrichment(self):
        """Test basic SBOM generation and enrichment."""
        generator = SBOMGenerator()
        enricher = VulnerabilityEnricher()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Create a simple Python project
            (tmppath / "requirements.txt").write_text("click==8.0.0")
            
            # Generate SBOM
            sbom = await generator.generate_sbom(
                project_path=tmppath,
                project_name="test-project",
                include_transitive=True
            )
            
            # Mock vulnerability enrichment to avoid API calls
            with patch.object(enricher, 'enrich_sbom') as mock_enrich:
                mock_result = MagicMock()
                mock_result.total_vulnerabilities = 0
                mock_result.scan_duration_seconds = 1.0
                mock_result.sbom = sbom
                mock_enrich.return_value = mock_result
                
                result = await enricher.enrich_sbom(sbom)
                
                assert result.total_vulnerabilities == 0
                assert result.sbom == sbom
                mock_enrich.assert_called_once()
    
    def test_get_supported_languages(self):
        """Test getting supported languages."""
        generator = SBOMGenerator()
        languages = generator.get_supported_languages()
        
        assert len(languages) > 0
        assert any(lang.value == "python" for lang in languages)
        assert any(lang.value == "javascript" for lang in languages)
    
    def test_get_supported_package_managers(self):
        """Test getting supported package managers."""
        generator = SBOMGenerator()
        package_managers = generator.get_supported_package_managers()
        
        assert len(package_managers) > 0
        assert any(pm.value == "pip" for pm in package_managers)
        assert any(pm.value == "npm" for pm in package_managers)


class TestCLIIntegration:
    """Test CLI integration."""
    
    def test_cli_detect_command(self):
        """Test the detect CLI command."""
        from dependency_canary.cli import cli
        from click.testing import CliRunner
        
        runner = CliRunner()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "requirements.txt").write_text("requests==2.25.1")
            
            result = runner.invoke(cli, ['detect', str(tmppath)])
            
            assert result.exit_code == 0
            assert "requirements.txt" in result.output
            assert "python" in result.output
            assert "pip" in result.output


if __name__ == "__main__":
    pytest.main([__file__])