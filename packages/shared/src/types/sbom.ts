export interface PackageReference {
  name: string;
  version: string;
}

export interface PackageStats {
  lastCommit?: string;
  weeklyDownloads?: number;
}

export interface PackageRisk {
  abandoned: boolean;
  typoSuspicion: number;
  newlyCreated: boolean;
  maintainerTrust: "low" | "medium" | "high";
}

export interface ExploitInfo {
  type: "POC" | "EXPLOIT" | "WEAPONIZED";
  url: string;
}

export interface AdvisoryReference {
  source: "GHSA" | "OSV" | "NVD";
  id: string;
}

export interface Vulnerability {
  id: string;
  source: "NVD" | "OSV" | "GHSA";
  cvss: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  published: string;
  summary: string;
  affectedRanges: string[];
  exploits?: ExploitInfo[];
  advisories?: AdvisoryReference[];
}

export interface Package {
  name: string;
  version: string;
  eco: "npm" | "pypi" | "go" | "maven" | "nuget" | "cargo" | "composer";
  direct: boolean;
  serviceRefs?: string[];
  license?: string;
  repoUrl?: string;
  stats?: PackageStats;
  risk?: PackageRisk;
  vulns?: Vulnerability[];
  requires?: PackageReference[];
  requiredBy?: PackageReference[];
}

export interface TopRisk {
  package: string;
  version: string;
  reason: string;
  score: number;
}

export interface SBOMSummary {
  counts: {
    packages: number;
    direct: number;
    transitive: number;
    vulns: number;
    critical: number;
    high: number;
    medium?: number;
    low?: number;
  };
  topRisks: TopRisk[];
}

export interface ProjectMetadata {
  languages: string[];
  services: string[];
}

export interface EnrichedSBOM {
  projectId: string;
  generatedAt: string;
  metadata: ProjectMetadata;
  packages: Package[];
  summary: SBOMSummary;
}