"""
Supply chain intelligence gathering using free APIs.
"""

import asyncio
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import httpx
from loguru import logger

from .models import Package


@dataclass
class PackageIntelligence:
    """Rich package intelligence data."""
    package_name: str
    package_manager: str
    version: str
    
    # Registry data
    weekly_downloads: Optional[int] = None
    total_downloads: Optional[int] = None
    maintainers: List[str] = None
    upload_time: Optional[datetime] = None
    project_urls: Dict[str, str] = None
    dependencies_count: int = 0
    
    # Risk signals
    is_very_new: bool = False  # < 30 days old
    low_download_count: bool = False  # < 1000 weekly downloads
    suspicious_name: bool = False
    potential_typosquat: bool = False
    
    def __post_init__(self):
        if self.maintainers is None:
            self.maintainers = []
        if self.project_urls is None:
            self.project_urls = {}


@dataclass 
class SupplyChainRisk:
    """Supply chain risk assessment."""
    package_name: str
    risk_level: str  # "low", "medium", "high", "critical"
    risk_score: float  # 0-10
    risk_factors: List[str]
    recommendations: List[str]


class SupplyChainIntelligence:
    """Gather supply chain intelligence from free APIs."""
    
    def __init__(self):
        # Popular packages for typosquatting detection (cached)
        self.popular_packages = {
            "pip": [
                "requests", "urllib3", "setuptools", "certifi", "pip", "wheel", 
                "six", "python-dateutil", "s3transfer", "jmespath", "docutils",
                "pytz", "pyyaml", "rsa", "awscli", "boto3", "numpy", "click",
                "colorama", "packaging", "pyparsing", "attrs", "jsonschema",
                "pycparser", "cffi", "cryptography", "idna", "charset-normalizer"
            ],
            "npm": [
                "lodash", "react", "chalk", "commander", "express", "debug", 
                "mkdirp", "classnames", "prop-types", "moment", "request",
                "underscore", "async", "colors", "minimist", "fs-extra",
                "semver", "glob", "yargs", "axios", "jquery", "webpack",
                "babel-core", "typescript", "eslint", "jest", "mocha"
            ]
        }
    
    async def gather_package_intelligence(self, packages: List[Package]) -> List[PackageIntelligence]:
        """Gather intelligence for a batch of packages."""
        results = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            tasks = []
            for package in packages:
                if package.package_manager in ["pip", "poetry", "pipenv"]:
                    tasks.append(self._analyze_pypi_package(client, package))
                elif package.package_manager in ["npm", "yarn", "pnpm"]:
                    tasks.append(self._analyze_npm_package(client, package))
                else:
                    # Basic analysis for other package managers
                    tasks.append(self._analyze_generic_package(package))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and return valid results
            valid_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to analyze {packages[i].name}: {result}")
                    # Create basic intelligence record
                    valid_results.append(PackageIntelligence(
                        package_name=packages[i].name,
                        package_manager=packages[i].package_manager,
                        version=packages[i].version
                    ))
                else:
                    valid_results.append(result)
            
            return valid_results
    
    async def _analyze_pypi_package(self, client: httpx.AsyncClient, package: Package) -> PackageIntelligence:
        """Analyze PyPI package using free APIs."""
        intel = PackageIntelligence(
            package_name=package.name,
            package_manager=package.package_manager,
            version=package.version
        )
        
        try:
            # Get package metadata from PyPI
            resp = await client.get(f"https://pypi.org/pypi/{package.name}/json")
            if resp.status_code == 200:
                data = resp.json()
                info = data.get("info", {})
                
                intel.maintainers = [info.get("maintainer", ""), info.get("author", "")]
                intel.maintainers = [m for m in intel.maintainers if m]
                intel.project_urls = info.get("project_urls") or {}
                
                # Get upload time for this version
                releases = data.get("releases", {})
                if package.version in releases and releases[package.version]:
                    upload_time_str = releases[package.version][0].get("upload_time")
                    if upload_time_str:
                        intel.upload_time = datetime.fromisoformat(upload_time_str.replace('Z', '+00:00'))
                        days_old = (datetime.now(intel.upload_time.tzinfo) - intel.upload_time).days
                        intel.is_very_new = days_old < 30
                
                # Count dependencies if available
                requires_dist = info.get("requires_dist") or []
                intel.dependencies_count = len(requires_dist)
        
        except Exception as e:
            logger.debug(f"Failed to get PyPI data for {package.name}: {e}")
        
        try:
            # Get download stats from pypistats (free)
            resp = await client.get(f"https://pypistats.org/api/packages/{package.name}/recent")
            if resp.status_code == 200:
                data = resp.json()
                last_week = data.get("data", {}).get("last_week", 0)
                intel.weekly_downloads = last_week
                intel.low_download_count = last_week < 1000
        
        except Exception as e:
            logger.debug(f"Failed to get pypistats for {package.name}: {e}")
        
        # Risk analysis
        intel.suspicious_name = self._check_suspicious_name(package.name)
        intel.potential_typosquat = self._check_typosquatting(package.name, "pip")
        
        return intel
    
    async def _analyze_npm_package(self, client: httpx.AsyncClient, package: Package) -> PackageIntelligence:
        """Analyze npm package using free APIs."""
        intel = PackageIntelligence(
            package_name=package.name,
            package_manager=package.package_manager,
            version=package.version
        )
        
        try:
            # Get package metadata from npm registry
            resp = await client.get(f"https://registry.npmjs.org/{package.name}")
            if resp.status_code == 200:
                data = resp.json()
                
                # Maintainers
                maintainers = data.get("maintainers", [])
                intel.maintainers = [m.get("name", "") for m in maintainers if isinstance(m, dict)]
                
                # Repository info
                repository = data.get("repository", {})
                if isinstance(repository, dict) and repository.get("url"):
                    intel.project_urls = {"repository": repository["url"]}
                
                # Upload time for this version
                time_data = data.get("time", {})
                if package.version in time_data:
                    upload_time_str = time_data[package.version]
                    intel.upload_time = datetime.fromisoformat(upload_time_str.replace('Z', '+00:00'))
                    days_old = (datetime.now(intel.upload_time.tzinfo) - intel.upload_time).days
                    intel.is_very_new = days_old < 30
                
                # Dependencies count
                versions = data.get("versions", {})
                if package.version in versions:
                    deps = versions[package.version].get("dependencies", {})
                    intel.dependencies_count = len(deps)
        
        except Exception as e:
            logger.debug(f"Failed to get npm registry data for {package.name}: {e}")
        
        try:
            # Get download stats from npm API
            resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{package.name}")
            if resp.status_code == 200:
                data = resp.json()
                downloads = data.get("downloads", 0)
                intel.weekly_downloads = downloads
                intel.low_download_count = downloads < 1000
        
        except Exception as e:
            logger.debug(f"Failed to get npm download stats for {package.name}: {e}")
        
        # Risk analysis
        intel.suspicious_name = self._check_suspicious_name(package.name)
        intel.potential_typosquat = self._check_typosquatting(package.name, "npm")
        
        return intel
    
    async def _analyze_generic_package(self, package: Package) -> PackageIntelligence:
        """Basic analysis for packages without specific API support."""
        intel = PackageIntelligence(
            package_name=package.name,
            package_manager=package.package_manager,
            version=package.version
        )
        
        # Only do heuristic-based analysis
        intel.suspicious_name = self._check_suspicious_name(package.name)
        ecosystem = "pip" if package.package_manager in ["cargo", "bundler"] else "npm"
        intel.potential_typosquat = self._check_typosquatting(package.name, ecosystem)
        
        return intel
    
    def _check_suspicious_name(self, package_name: str) -> bool:
        """Check for suspicious naming patterns."""
        suspicious_patterns = [
            r".*test.*", r".*temp.*", r".*debug.*",  # Test/temp packages
            r"[0-9]+$",  # Packages ending in numbers
            r".*[_-](utils?|helpers?|tools?)$",  # Generic utility names
            r"^[a-z]{1,3}$",  # Very short names (often squatted)
            r".*[_-]v?[0-9]+[_-].*",  # Version numbers in package names
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        return False
    
    def _check_typosquatting(self, package_name: str, ecosystem: str) -> bool:
        """Check if package name is similar to popular packages."""
        if ecosystem not in self.popular_packages:
            return False
        
        for popular in self.popular_packages[ecosystem]:
            distance = self._levenshtein_distance(package_name.lower(), popular.lower())
            # If the package name is very similar but not identical
            if 1 <= distance <= 2 and package_name.lower() != popular.lower():
                return True
        return False
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) > len(s2):
            s1, s2 = s2, s1
        
        distances = range(len(s1) + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2 + 1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
        return distances[-1]
    
    def calculate_supply_chain_risk(self, intel: PackageIntelligence) -> SupplyChainRisk:
        """Calculate overall supply chain risk score."""
        risk_factors = []
        risk_score = 0.0
        
        # Risk factor: Very new package
        if intel.is_very_new:
            risk_factors.append("Package is less than 30 days old")
            risk_score += 2.0
        
        # Risk factor: Low download count
        if intel.low_download_count:
            risk_factors.append("Low download count (< 1000/week)")
            risk_score += 1.5
        
        # Risk factor: Suspicious naming
        if intel.suspicious_name:
            risk_factors.append("Suspicious naming pattern detected")
            risk_score += 2.5
        
        # Risk factor: Potential typosquatting
        if intel.potential_typosquat:
            risk_factors.append("Potential typosquatting attempt")
            risk_score += 4.0
        
        # Risk factor: No maintainer info
        if not intel.maintainers:
            risk_factors.append("No maintainer information available")
            risk_score += 1.0
        
        # Risk factor: No project URLs
        if not intel.project_urls:
            risk_factors.append("No project repository or homepage")
            risk_score += 1.0
        
        # Determine risk level
        if risk_score >= 6.0:
            risk_level = "critical"
        elif risk_score >= 4.0:
            risk_level = "high"
        elif risk_score >= 2.0:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate recommendations
        recommendations = []
        if intel.potential_typosquat:
            recommendations.append("Verify package name spelling - may be typosquatting")
        if intel.is_very_new:
            recommendations.append("Consider using more established package versions")
        if intel.low_download_count:
            recommendations.append("Review if this package is still maintained")
        if not intel.project_urls:
            recommendations.append("Verify package authenticity through other channels")
        
        return SupplyChainRisk(
            package_name=intel.package_name,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            recommendations=recommendations
        )