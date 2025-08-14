import { EnrichedSBOM, Package, Vulnerability, VectorDocument } from "@dependency-canary/shared";

export class SBOMProcessor {
  processToDocuments(sbom: EnrichedSBOM): VectorDocument[] {
    const documents: VectorDocument[] = [];

    documents.push({
      id: `project:${sbom.projectId}`,
      content: this.createProjectSummary(sbom),
      metadata: {
        type: "project",
        projectId: sbom.projectId,
        ...sbom.metadata,
      },
    });

    for (const service of sbom.metadata.services) {
      documents.push({
        id: `service:${sbom.projectId}:${service}`,
        content: this.createServiceSummary(sbom, service),
        metadata: {
          type: "service",
          projectId: sbom.projectId,
          service,
        },
      });
    }

    for (const pkg of sbom.packages) {
      documents.push({
        id: `package:${sbom.projectId}:${pkg.name}:${pkg.version}`,
        content: this.createPackageSummary(pkg),
        metadata: {
          type: "package",
          projectId: sbom.projectId,
          packageName: pkg.name,
          packageVersion: pkg.version,
          ecosystem: pkg.eco,
          isDirect: pkg.direct,
          services: pkg.serviceRefs || [],
          severity: this.getHighestSeverity(pkg),
        },
      });

      if (pkg.vulns) {
        for (const vuln of pkg.vulns) {
          documents.push({
            id: `vuln:${sbom.projectId}:${vuln.id}`,
            content: this.createVulnerabilityContent(pkg, vuln),
            metadata: {
              type: "vulnerability",
              projectId: sbom.projectId,
              vulnerabilityId: vuln.id,
              packageName: pkg.name,
              packageVersion: pkg.version,
              severity: vuln.severity,
              cvss: vuln.cvss,
              hasExploits: (vuln.exploits?.length || 0) > 0,
              services: pkg.serviceRefs || [],
            },
          });
        }
      }
    }

    return documents;
  }

  private createProjectSummary(sbom: EnrichedSBOM): string {
    const { summary } = sbom;
    return `Project Analysis Summary:
- Total packages: ${summary.counts.packages} (${summary.counts.direct} direct, ${summary.counts.transitive} transitive)
- Languages: ${sbom.metadata.languages.join(", ")}
- Services: ${sbom.metadata.services.join(", ")}
- Vulnerabilities: ${summary.counts.vulns} total (${summary.counts.critical} critical, ${summary.counts.high} high, ${summary.counts.medium || 0} medium, ${summary.counts.low || 0} low)
- Top risks: ${summary.topRisks.map(r => `${r.package}@${r.version} (${r.reason})`).join("; ")}`;
  }

  private createServiceSummary(sbom: EnrichedSBOM, service: string): string {
    const packages = sbom.packages.filter(pkg => pkg.serviceRefs?.includes(service));
    const vulnCount = packages.reduce((sum, pkg) => sum + (pkg.vulns?.length || 0), 0);
    const directCount = packages.filter(pkg => pkg.direct).length;

    return `Service "${service}" Analysis:
- Dependencies: ${packages.length} packages (${directCount} direct)
- Vulnerabilities: ${vulnCount} total
- Key packages: ${packages.filter(pkg => pkg.direct).map(pkg => `${pkg.name}@${pkg.version}`).join(", ")}`;
  }

  private createPackageSummary(pkg: Package): string {
    const vulnSummary = pkg.vulns?.length 
      ? `Vulnerabilities: ${pkg.vulns.length} (${pkg.vulns.filter(v => v.severity === "CRITICAL").length} critical, ${pkg.vulns.filter(v => v.severity === "HIGH").length} high)`
      : "No known vulnerabilities";
    
    const riskFactors = [];
    if (pkg.risk?.abandoned) riskFactors.push("abandoned");
    if (pkg.risk?.newlyCreated) riskFactors.push("newly created");
    if (pkg.risk?.typoSuspicion && pkg.risk.typoSuspicion > 0.5) riskFactors.push("typosquatting risk");
    
    const riskSummary = riskFactors.length ? `Risk factors: ${riskFactors.join(", ")}` : "Low risk profile";

    return `Package: ${pkg.name}@${pkg.version}
- Ecosystem: ${pkg.eco}
- Type: ${pkg.direct ? "Direct dependency" : "Transitive dependency"}
- License: ${pkg.license || "Unknown"}
- Services: ${pkg.serviceRefs?.join(", ") || "None specified"}
- ${vulnSummary}
- ${riskSummary}
- Dependencies: ${pkg.requires?.length || 0} direct dependencies
- Used by: ${pkg.requiredBy?.length || 0} packages`;
  }

  private createVulnerabilityContent(pkg: Package, vuln: Vulnerability): string {
    const exploitInfo = vuln.exploits?.length 
      ? `Exploits available: ${vuln.exploits.map(e => e.type).join(", ")}`
      : "No known exploits";

    return `Vulnerability: ${vuln.id}
- Package: ${pkg.name}@${pkg.version}
- Severity: ${vuln.severity} (CVSS: ${vuln.cvss})
- Published: ${vuln.published}
- Summary: ${vuln.summary}
- Affected ranges: ${vuln.affectedRanges.join(", ")}
- ${exploitInfo}
- Services affected: ${pkg.serviceRefs?.join(", ") || "Unknown"}
- Package type: ${pkg.direct ? "Direct dependency" : "Transitive dependency"}`;
  }

  private getHighestSeverity(pkg: Package): string {
    if (!pkg.vulns?.length) return "NONE";
    
    const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    
    for (const severity of severityOrder) {
      if (pkg.vulns.some(v => v.severity === severity)) {
        return severity;
      }
    }
    
    return "NONE";
  }
}