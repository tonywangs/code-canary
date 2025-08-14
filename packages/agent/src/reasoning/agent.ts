import OpenAI from "openai";
import { 
  AgentAnswer, 
  VectorStore, 
  VectorStoreQuery, 
  EnrichedSBOM,
  RemediationStep,
  Package,
  Vulnerability
} from "@dependency-canary/shared";

export class SecurityAgent {
  private openai: OpenAI;
  private vectorStore: VectorStore;
  private sbomCache: Map<string, EnrichedSBOM> = new Map();

  constructor(vectorStore: VectorStore, openaiApiKey?: string) {
    this.vectorStore = vectorStore;
    this.openai = new OpenAI({
      apiKey: openaiApiKey || process.env.OPENAI_API_KEY,
    });
  }

  async indexSBOM(sbom: EnrichedSBOM): Promise<void> {
    this.sbomCache.set(sbom.projectId, sbom);
  }

  async ask(projectId: string, question: string): Promise<AgentAnswer> {
    const sbom = this.sbomCache.get(projectId);
    if (!sbom) {
      throw new Error(`SBOM not found for project ${projectId}`);
    }

    const context = await this.gatherContext(projectId, question);
    
    const prompt = this.buildPrompt(question, context, sbom);
    
    let response: any;
    try {
      const completion = await this.openai.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
      });
      
      response = JSON.parse(completion.choices[0].message.content || "{}");
    } catch (error) {
      response = this.generateFallbackResponse(question, sbom);
    }

    const remediationPlan = this.generateRemediationPlan(sbom);

    return {
      question,
      answerMarkdown: response.answer || this.generateFallbackAnswer(question, sbom),
      keyFindings: response.keyFindings || this.extractKeyFindings(sbom),
      remediationPlan,
      citations: response.citations || this.generateCitations(sbom),
    };
  }

  private async gatherContext(projectId: string, question: string): Promise<any> {
    const queries: VectorStoreQuery[] = [
      { query: question, k: 5 },
      { query: question, k: 3, filter: { type: "vulnerability", severity: "CRITICAL" } },
      { query: question, k: 3, filter: { type: "vulnerability", severity: "HIGH" } },
      { query: question, k: 2, filter: { type: "package", isDirect: true } },
    ];

    const results = await Promise.all(
      queries.map(query => this.vectorStore.search(query))
    );

    return {
      relevantDocuments: results[0],
      criticalVulns: results[1],
      highVulns: results[2],
      directPackages: results[3],
    };
  }

  private buildPrompt(question: string, context: any, sbom: EnrichedSBOM): string {
    return `You are a cybersecurity expert analyzing a software project's dependency graph for vulnerabilities and supply chain risks.

QUESTION: ${question}

PROJECT CONTEXT:
- Project ID: ${sbom.projectId}
- Languages: ${sbom.metadata.languages.join(", ")}
- Services: ${sbom.metadata.services.join(", ")}
- Total packages: ${sbom.summary.counts.packages}
- Vulnerabilities: ${sbom.summary.counts.vulns} total (${sbom.summary.counts.critical} critical, ${sbom.summary.counts.high} high)

RELEVANT CONTEXT:
${context.relevantDocuments.map((r: any) => `- ${r.document.content.substring(0, 200)}...`).join("\n")}

CRITICAL VULNERABILITIES:
${context.criticalVulns.map((r: any) => `- ${r.document.content.substring(0, 150)}...`).join("\n")}

HIGH SEVERITY VULNERABILITIES:
${context.highVulns.map((r: any) => `- ${r.document.content.substring(0, 150)}...`).join("\n")}

Please provide a detailed analysis and answer the question. Focus on:
1. Direct security implications
2. Business impact and risk assessment
3. Specific actionable recommendations
4. Prioritization based on severity and exploitability

Respond in JSON format:
{
  "answer": "Detailed markdown response with analysis and recommendations",
  "keyFindings": [{"nodeId": "package_or_vuln_id", "reason": "why this is significant"}],
  "citations": [{"type": "package|vuln|advisory", "id": "identifier"}]
}`;
  }

  private generateRemediationPlan(sbom: EnrichedSBOM): RemediationStep[] {
    const steps: RemediationStep[] = [];
    
    const criticalVulns = this.findCriticalVulnerabilities(sbom);
    const highVulns = this.findHighVulnerabilities(sbom);
    
    if (criticalVulns.length > 0) {
      const affectedPackages = criticalVulns.map(v => v.packageName);
      steps.push({
        title: "Immediately address critical vulnerabilities",
        impact: "HIGH",
        actions: [
          "Update affected packages to patched versions",
          "If patches unavailable, implement temporary mitigations",
          "Review and test all changes in staging environment"
        ],
        affectedPackages,
        estimatedBreakage: this.estimateBreakageRisk(criticalVulns, sbom),
      });
    }

    if (highVulns.length > 0) {
      const affectedPackages = highVulns.map(v => v.packageName);
      steps.push({
        title: "Upgrade packages with high-severity vulnerabilities",
        impact: "MEDIUM",
        actions: [
          "Plan coordinated update of high-risk packages",
          "Test compatibility with existing codebase",
          "Monitor for regression issues"
        ],
        affectedPackages,
        estimatedBreakage: this.estimateBreakageRisk(highVulns, sbom),
      });
    }

    const abandonedPackages = this.findAbandonedPackages(sbom);
    if (abandonedPackages.length > 0) {
      steps.push({
        title: "Replace abandoned packages",
        impact: "MEDIUM",
        actions: [
          "Research actively maintained alternatives",
          "Plan migration strategy",
          "Update documentation and dependencies"
        ],
        affectedPackages: abandonedPackages.map(p => `${p.name}@${p.version}`),
        estimatedBreakage: "MEDIUM",
      });
    }

    return steps;
  }

  private findCriticalVulnerabilities(sbom: EnrichedSBOM): Array<{packageName: string, vulnId: string, packageVersion: string}> {
    const critical: Array<{packageName: string, vulnId: string, packageVersion: string}> = [];
    
    for (const pkg of sbom.packages) {
      if (pkg.vulns) {
        for (const vuln of pkg.vulns) {
          if (vuln.severity === "CRITICAL") {
            critical.push({
              packageName: pkg.name,
              vulnId: vuln.id,
              packageVersion: pkg.version
            });
          }
        }
      }
    }
    
    return critical;
  }

  private findHighVulnerabilities(sbom: EnrichedSBOM): Array<{packageName: string, vulnId: string, packageVersion: string}> {
    const high: Array<{packageName: string, vulnId: string, packageVersion: string}> = [];
    
    for (const pkg of sbom.packages) {
      if (pkg.vulns) {
        for (const vuln of pkg.vulns) {
          if (vuln.severity === "HIGH") {
            high.push({
              packageName: pkg.name,
              vulnId: vuln.id,
              packageVersion: pkg.version
            });
          }
        }
      }
    }
    
    return high;
  }

  private findAbandonedPackages(sbom: EnrichedSBOM): Package[] {
    return sbom.packages.filter(pkg => pkg.risk?.abandoned === true);
  }

  private estimateBreakageRisk(vulns: Array<{packageName: string, vulnId: string, packageVersion: string}>, sbom: EnrichedSBOM): "LOW" | "MEDIUM" | "HIGH" {
    const affectedDirectDeps = vulns.filter(v => {
      const pkg = sbom.packages.find(p => p.name === v.packageName);
      return pkg?.direct === true;
    }).length;

    if (affectedDirectDeps >= 3) return "HIGH";
    if (affectedDirectDeps >= 1) return "MEDIUM";
    return "LOW";
  }

  private generateFallbackResponse(question: string, sbom: EnrichedSBOM): any {
    return {
      answer: this.generateFallbackAnswer(question, sbom),
      keyFindings: this.extractKeyFindings(sbom),
      citations: this.generateCitations(sbom),
    };
  }

  private generateFallbackAnswer(question: string, sbom: EnrichedSBOM): string {
    const criticalCount = sbom.summary.counts.critical;
    const highCount = sbom.summary.counts.high;
    
    if (question.toLowerCase().includes("critical")) {
      if (criticalCount > 0) {
        return `## Critical Vulnerability Analysis\n\nYour project has **${criticalCount} critical vulnerabilities** that require immediate attention. These vulnerabilities pose significant security risks and should be addressed as the highest priority.\n\n### Immediate Actions Required\n1. Review all critical vulnerabilities in detail\n2. Update affected packages to patched versions\n3. Implement temporary mitigations if patches are unavailable\n4. Test all changes thoroughly before deployment`;
      } else {
        return `## Critical Vulnerability Status\n\nGood news! Your project currently has **no critical vulnerabilities**. However, you do have ${highCount} high-severity vulnerabilities that should still be addressed promptly.`;
      }
    }

    if (question.toLowerCase().includes("upgrade")) {
      const topRisks = sbom.summary.topRisks.slice(0, 3);
      return `## Upgrade Recommendations\n\nBased on the dependency analysis, here are the priority upgrades:\n\n${topRisks.map((risk, i) => `${i + 1}. **${risk.package}@${risk.version}** - ${risk.reason} (Risk score: ${risk.score})`).join('\n')}\n\n### Recommended Approach\n1. Start with the highest risk packages\n2. Test each upgrade individually\n3. Monitor for compatibility issues`;
    }

    return `## Dependency Analysis Summary\n\nYour project contains ${sbom.summary.counts.packages} total packages with ${sbom.summary.counts.vulns} known vulnerabilities:\n\n- **Critical**: ${criticalCount}\n- **High**: ${highCount}\n- **Medium**: ${sbom.summary.counts.medium || 0}\n- **Low**: ${sbom.summary.counts.low || 0}\n\n### Top Risk Packages\n${sbom.summary.topRisks.slice(0, 3).map(r => `- ${r.package}@${r.version}: ${r.reason}`).join('\n')}`;
  }

  private extractKeyFindings(sbom: EnrichedSBOM): Array<{nodeId: string, reason: string}> {
    const findings: Array<{nodeId: string, reason: string}> = [];
    
    sbom.summary.topRisks.forEach(risk => {
      findings.push({
        nodeId: `package:${sbom.projectId}:${risk.package}:${risk.version}`,
        reason: risk.reason,
      });
    });

    return findings;
  }

  private generateCitations(sbom: EnrichedSBOM): Array<{type: "package" | "vuln" | "advisory", id: string}> {
    const citations: Array<{type: "package" | "vuln" | "advisory", id: string}> = [];
    
    sbom.summary.topRisks.forEach(risk => {
      citations.push({
        type: "package",
        id: `${risk.package}@${risk.version}`,
      });
    });

    let vulnCount = 0;
    for (const pkg of sbom.packages) {
      if (pkg.vulns && vulnCount < 5) {
        for (const vuln of pkg.vulns) {
          if (vulnCount >= 5) break;
          citations.push({
            type: "vuln",
            id: vuln.id,
          });
          vulnCount++;
        }
      }
    }

    return citations;
  }
}