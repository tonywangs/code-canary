import { SecurityAgent, createVectorStore } from '@dependency-canary/agent';
import { EnrichedSBOM } from '@dependency-canary/shared';

class AgentService {
  private static instance: AgentService;
  private agent: SecurityAgent;
  private indexedProjects: Set<string> = new Set();
  private sbomCache: Map<string, EnrichedSBOM> = new Map();

  private constructor() {
    this.agent = new SecurityAgent(createVectorStore());
  }

  public static getInstance(): AgentService {
    if (!AgentService.instance) {
      AgentService.instance = new AgentService();
    }
    return AgentService.instance;
  }

  public async indexSBOM(sbom: EnrichedSBOM): Promise<void> {
    await this.agent.indexSBOM(sbom);
    this.indexedProjects.add(sbom.projectId);
    this.sbomCache.set(sbom.projectId, sbom);
    console.log(`Indexed SBOM for project: ${sbom.projectId}`);
  }

  public async ask(projectId: string, question: string) {
    if (!this.indexedProjects.has(projectId)) {
      throw new Error(`SBOM not found for project ${projectId}. Please ensure the project has been scanned and enriched first.`);
    }
    return await this.agent.ask(projectId, question);
  }

  public isProjectIndexed(projectId: string): boolean {
    return this.indexedProjects.has(projectId);
  }

  public getIndexedProjects(): string[] {
    return Array.from(this.indexedProjects);
  }

  public getSBOM(projectId: string): EnrichedSBOM | undefined {
    return this.sbomCache.get(projectId);
  }
}

export const agentService = AgentService.getInstance(); 