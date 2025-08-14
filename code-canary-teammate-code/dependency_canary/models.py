"""
Data models for SBOM, dependencies, and vulnerabilities.
"""

from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field
from enum import Enum

class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

class DependencyType(Enum):
    """Types of dependencies."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "dev"
    OPTIONAL = "optional"

class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"

class Package(BaseModel):
    """Represents a software package."""
    name: str
    version: str
    language: str
    package_manager: str
    namespace: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    checksum: Optional[str] = None
    
    @property
    def purl(self) -> str:
        """Generate Package URL (PURL) for this package."""
        namespace_part = f"{self.namespace}/" if self.namespace else ""
        return f"pkg:{self.package_manager}/{namespace_part}{self.name}@{self.version}"

class Dependency(BaseModel):
    """Represents a dependency relationship."""
    package: Package
    dependency_type: DependencyType
    scope: Optional[str] = None  # e.g., "runtime", "test", "build"
    is_optional: bool = False
    parent: Optional[str] = None  # PURL of parent package
    depth: int = 0  # Depth in dependency tree (0 = direct)
    
class Vulnerability(BaseModel):
    """Represents a security vulnerability."""
    id: str  # CVE, GHSA, OSV ID
    source: str  # "nvd", "osv", "ghsa"
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    
    # Affected package information
    affected_packages: List[str] = Field(default_factory=list)  # PURLs
    fixed_versions: List[str] = Field(default_factory=list)
    vulnerable_versions: List[str] = Field(default_factory=list)
    
    # References and metadata
    references: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None
    
class RiskFactor(BaseModel):
    """Represents a risk factor for a package."""
    type: str  # "typosquat", "abandoned", "malicious", "maintainer"
    severity: RiskLevel
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)  # 0-1 confidence score

class PackageRisk(BaseModel):
    """Risk assessment for a package."""
    package_purl: str
    overall_risk: RiskLevel
    risk_score: float = Field(ge=0.0, le=10.0)  # 0-10 risk score
    
    # Risk factors
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    
    # Package metadata for risk assessment
    age_days: Optional[int] = None
    last_update_days: Optional[int] = None
    download_count: Optional[int] = None
    maintainer_count: Optional[int] = None
    
class SBOM(BaseModel):
    """Software Bill of Materials."""
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    format_version: str = "1.0"
    tool_name: str = "code-canary"
    tool_version: str = "0.1.0"
    
    # Project information
    project_name: Optional[str] = None
    project_version: Optional[str] = None
    project_path: Optional[str] = None
    
    # Dependencies
    packages: List[Package] = Field(default_factory=list)
    dependencies: List[Dependency] = Field(default_factory=list)
    
    # Statistics
    total_packages: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0
    languages: Set[str] = Field(default_factory=set)
    package_managers: Set[str] = Field(default_factory=set)
    
    def add_package(self, package: Package, dependency: Dependency):
        """Add a package and its dependency relationship to the SBOM."""
        # Check if package already exists
        existing_package = self.get_package_by_purl(package.purl)
        if not existing_package:
            self.packages.append(package)
            self.languages.add(package.language)
            self.package_managers.add(package.package_manager)
        
        # Add dependency relationship
        self.dependencies.append(dependency)
        
        # Update statistics
        self._update_statistics()
    
    def get_package_by_purl(self, purl: str) -> Optional[Package]:
        """Get package by its PURL."""
        for package in self.packages:
            if package.purl == purl:
                return package
        return None
    
    def get_direct_dependencies(self) -> List[Dependency]:
        """Get all direct dependencies."""
        return [dep for dep in self.dependencies if dep.dependency_type == DependencyType.DIRECT]
    
    def get_transitive_dependencies(self) -> List[Dependency]:
        """Get all transitive dependencies."""
        return [dep for dep in self.dependencies if dep.dependency_type == DependencyType.TRANSITIVE]
    
    def get_dependencies_by_language(self, language: str) -> List[Dependency]:
        """Get dependencies for a specific language."""
        return [dep for dep in self.dependencies if dep.package.language == language]
    
    def _update_statistics(self):
        """Update SBOM statistics."""
        self.total_packages = len(self.packages)
        self.direct_dependencies = len(self.get_direct_dependencies())
        self.transitive_dependencies = len(self.get_transitive_dependencies())

class ScanResult(BaseModel):
    """Complete scan result including SBOM and risk analysis."""
    sbom: SBOM
    risks: List[PackageRisk] = Field(default_factory=list)
    
    # Summary statistics
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    # Risk summary
    critical_risk_packages: int = 0
    high_risk_packages: int = 0
    medium_risk_packages: int = 0
    low_risk_packages: int = 0
    
    # Scan metadata
    scan_duration_seconds: Optional[float] = None
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Supply chain intelligence (optional)
    supply_chain_intelligence: Optional[List[Dict[str, Any]]] = None
    
    def add_package_risk(self, risk: PackageRisk):
        """Add a package risk assessment."""
        self.risks.append(risk)
        self._update_risk_statistics()
    
    def get_high_risk_packages(self) -> List[PackageRisk]:
        """Get packages with high or critical risk."""
        return [risk for risk in self.risks 
                if risk.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
    
    def get_vulnerabilities_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Get all vulnerabilities of a specific severity."""
        vulnerabilities = []
        for risk in self.risks:
            vulnerabilities.extend([v for v in risk.vulnerabilities if v.severity == severity])
        return vulnerabilities
    
    def _update_risk_statistics(self):
        """Update risk and vulnerability statistics."""
        # Count vulnerabilities by severity
        all_vulnerabilities = []
        for risk in self.risks:
            all_vulnerabilities.extend(risk.vulnerabilities)
        
        self.total_vulnerabilities = len(all_vulnerabilities)
        self.critical_vulnerabilities = len([v for v in all_vulnerabilities if v.severity == SeverityLevel.CRITICAL])
        self.high_vulnerabilities = len([v for v in all_vulnerabilities if v.severity == SeverityLevel.HIGH])
        self.medium_vulnerabilities = len([v for v in all_vulnerabilities if v.severity == SeverityLevel.MEDIUM])
        self.low_vulnerabilities = len([v for v in all_vulnerabilities if v.severity == SeverityLevel.LOW])
        
        # Count packages by risk level
        self.critical_risk_packages = len([r for r in self.risks if r.overall_risk == RiskLevel.CRITICAL])
        self.high_risk_packages = len([r for r in self.risks if r.overall_risk == RiskLevel.HIGH])
        self.medium_risk_packages = len([r for r in self.risks if r.overall_risk == RiskLevel.MEDIUM])
        self.low_risk_packages = len([r for r in self.risks if r.overall_risk == RiskLevel.LOW])

class RemediationSuggestion(BaseModel):
    """Represents a remediation suggestion for vulnerabilities."""
    package_purl: str
    current_version: str
    suggested_version: Optional[str] = None
    action: str  # "update", "remove", "replace", "patch"
    reason: str
    impact: str  # "breaking", "non-breaking", "unknown"
    effort: str  # "low", "medium", "high"
    vulnerabilities_fixed: List[str] = Field(default_factory=list)  # Vulnerability IDs
