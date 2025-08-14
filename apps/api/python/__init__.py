"""
Code Canary - SBOM and Vulnerability Scanner

Generates SBOMs and enriches them with public vulnerability data to help
identify risks in software supply chains.
"""

__version__ = "0.1.0"
__author__ = "Code Canary Team"

from .sbom import SBOMGenerator
from .vulnerability import VulnerabilityEnricher
from .modal_workers import ModalSBOMService

__all__ = [
    "SBOMGenerator", 
    "VulnerabilityEnricher",
    "ModalSBOMService",
]
