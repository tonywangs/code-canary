#!/usr/bin/env python3
"""
Test Modal integration functionality.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from dependency_canary.modal_workers import ModalSBOMService
from dependency_canary.models import SBOM, Package, ScanResult


class TestModalWorkers:
    """Test Modal worker functions."""
    
    @pytest.mark.asyncio
    async def test_modal_service_fallback(self):
        """Test Modal service falls back to local processing on failure."""
        service = ModalSBOMService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "requirements.txt").write_text("requests==2.25.1")
            
            # Mock Modal worker to fail
            with patch('dependency_canary.modal_workers.generate_sbom_worker') as mock_worker:
                mock_worker.remote.call = AsyncMock(side_effect=Exception("Modal unavailable"))
                
                # Mock local SBOM generator
                with patch('dependency_canary.sbom.SBOMGenerator.generate_sbom') as mock_local:
                    expected_sbom = SBOM(project_name="test", project_path=str(tmppath))
                    mock_local.return_value = expected_sbom
                    
                    result = await service.generate_sbom_remote(tmppath, "test")
                    
                    assert result == expected_sbom
                    mock_local.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_modal_vulnerability_enrichment_fallback(self):
        """Test Modal vulnerability enrichment falls back to local processing."""
        service = ModalSBOMService()
        
        test_sbom = SBOM(project_name="test", project_path="/test")
        test_package = Package(
            name="test-package",
            version="1.0.0",
            language="python",
            package_manager="pip"
        )
        test_sbom.packages.append(test_package)
        
        # Mock Modal worker to fail
        with patch('dependency_canary.modal_workers.enrich_vulnerabilities_worker') as mock_worker:
            mock_worker.remote.call = AsyncMock(side_effect=Exception("Modal unavailable"))
            
            # Mock local vulnerability enricher
            with patch('dependency_canary.vulnerability.VulnerabilityEnricher.enrich_sbom') as mock_local:
                expected_result = ScanResult(sbom=test_sbom)
                mock_local.return_value = expected_result
                
                result = await service.enrich_vulnerabilities_remote(test_sbom)
                
                assert result == expected_result
                mock_local.assert_called_once()


class TestModalServiceIntegration:
    """Test Modal service integration."""
    
    def test_modal_service_initialization(self):
        """Test Modal service can be initialized."""
        service = ModalSBOMService()
        assert service.app is not None
    
    @pytest.mark.asyncio
    async def test_full_scan_with_mock_modal(self):
        """Test full scan with mocked Modal responses."""
        service = ModalSBOMService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "requirements.txt").write_text("click==8.0.0")
            
            # Mock successful Modal response
            mock_result = {
                "sbom": {
                    "project_name": "test",
                    "total_packages": 1,
                    "packages": [],
                    "dependencies": [],
                    "languages": ["python"],
                    "package_managers": ["pip"]
                },
                "total_vulnerabilities": 0,
                "risks": []
            }
            
            with patch('dependency_canary.modal_workers.full_scan_worker') as mock_worker:
                mock_worker.remote.call = AsyncMock(return_value=mock_result)
                
                result = await service.full_scan_remote(tmppath, "test")
                
                assert result.sbom.project_name == "test"
                assert result.total_vulnerabilities == 0


class TestModalWorkerFunctions:
    """Test individual Modal worker functions."""
    
    def test_worker_serialization(self):
        """Test that worker input/output can be serialized."""
        # Test SBOM serialization
        sbom = SBOM(project_name="test", project_path="/test")
        test_package = Package(
            name="test-package",
            version="1.0.0",
            language="python",
            package_manager="pip"
        )
        sbom.packages.append(test_package)
        sbom.total_packages = 1
        
        # Should be able to serialize/deserialize
        serialized = sbom.model_dump()
        assert isinstance(serialized, dict)
        assert serialized["project_name"] == "test"
        
        # Should be able to recreate from serialized data
        recreated = SBOM.model_validate(serialized)
        assert recreated.project_name == sbom.project_name
        assert len(recreated.packages) == len(sbom.packages)
    
    def test_scan_result_serialization(self):
        """Test that scan results can be serialized."""
        sbom = SBOM(project_name="test", project_path="/test")
        result = ScanResult(sbom=sbom)
        
        serialized = result.model_dump()
        assert isinstance(serialized, dict)
        assert "sbom" in serialized
        assert "total_vulnerabilities" in serialized
        
        # Should be able to recreate
        recreated = ScanResult.model_validate(serialized)
        assert recreated.sbom.project_name == result.sbom.project_name


class TestModalConfiguration:
    """Test Modal configuration and setup."""
    
    def test_modal_app_configuration(self):
        """Test that Modal app is properly configured."""
        from dependency_canary.modal_workers import app
        
        assert app is not None
        assert app.name == "renamed-project"
    
    def test_modal_image_configuration(self):
        """Test that Modal image is properly configured."""
        from dependency_canary.modal_workers import image
        
        assert image is not None
    
    def test_modal_volume_configuration(self):
        """Test that Modal volume is properly configured."""
        from dependency_canary.modal_workers import volume
        
        assert volume is not None


class TestModalErrorHandling:
    """Test error handling in Modal integration."""
    
    @pytest.mark.asyncio
    async def test_modal_timeout_handling(self):
        """Test handling of Modal timeouts."""
        service = ModalSBOMService()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            
            # Mock timeout error
            with patch('dependency_canary.modal_workers.generate_sbom_worker') as mock_worker:
                mock_worker.remote.call = AsyncMock(side_effect=TimeoutError("Modal timeout"))
                
                # Should fall back to local processing
                with patch('dependency_canary.sbom.SBOMGenerator.generate_sbom') as mock_local:
                    expected_sbom = SBOM(project_name="test", project_path=str(tmppath))
                    mock_local.return_value = expected_sbom
                    
                    result = await service.generate_sbom_remote(tmppath, "test")
                    
                    assert result == expected_sbom
                    mock_local.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_modal_network_error_handling(self):
        """Test handling of Modal network errors."""
        service = ModalSBOMService()
        
        test_sbom = SBOM(project_name="test", project_path="/test")
        
        # Mock network error
        with patch('dependency_canary.modal_workers.enrich_vulnerabilities_worker') as mock_worker:
            mock_worker.remote.call = AsyncMock(side_effect=ConnectionError("Network unavailable"))
            
            # Should fall back to local processing
            with patch('dependency_canary.vulnerability.VulnerabilityEnricher.enrich_sbom') as mock_local:
                expected_result = ScanResult(sbom=test_sbom)
                mock_local.return_value = expected_result
                
                result = await service.enrich_vulnerabilities_remote(test_sbom)
                
                assert result == expected_result
                mock_local.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])