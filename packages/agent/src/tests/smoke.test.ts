import { describe, it, expect, beforeAll } from 'vitest';
import { 
  createVectorStore, 
  createEmbedder, 
  SBOMProcessor, 
  SecurityAgent,
  InMemoryVectorStore,
  MockEmbedder
} from '../index';
import { MockModalClient, EnrichedSBOM } from '@dependency-canary/shared';

describe('Dependency Canary Smoke Tests', () => {
  let sbom: EnrichedSBOM;
  let agent: SecurityAgent;
  let vectorStore: InMemoryVectorStore;

  beforeAll(async () => {
    console.log('Setting up smoke test environment...');
    
    const mockClient = new MockModalClient();
    const scanResult = await mockClient.scan({
      projectRef: 'test-project',
      refType: 'git',
      ref: 'https://github.com/test/repo',
    });
    
    sbom = await mockClient.enrich(scanResult.jobId);
    
    const processor = new SBOMProcessor();
    const documents = processor.processToDocuments(sbom);
    
    const embedder = new MockEmbedder();
    for (const doc of documents) {
      doc.embedding = await embedder.embed(doc.content);
    }
    
    vectorStore = new InMemoryVectorStore();
    await vectorStore.addDocuments(documents);
    
    agent = new SecurityAgent(vectorStore);
    await agent.indexSBOM(sbom);
  });

  describe('Mock Data Generation', () => {
    it('should generate a valid SBOM with vulnerabilities', () => {
      expect(sbom).toBeDefined();
      expect(sbom.projectId).toBeTruthy();
      expect(sbom.packages).toHaveLength(8);
      expect(sbom.summary.counts.vulns).toBeGreaterThan(0);
      expect(sbom.summary.counts.critical).toBeGreaterThan(0);
      expect(sbom.summary.topRisks).toHaveLength(3);
    });

    it('should have packages with proper structure', () => {
      const pkg = sbom.packages[0];
      expect(pkg).toHaveProperty('name');
      expect(pkg).toHaveProperty('version');
      expect(pkg).toHaveProperty('eco');
      expect(pkg).toHaveProperty('direct');
      expect(pkg).toHaveProperty('vulns');
    });

    it('should have critical vulnerabilities', () => {
      const criticalVulns = sbom.packages
        .flatMap(pkg => pkg.vulns || [])
        .filter(vuln => vuln.severity === 'CRITICAL');
      
      expect(criticalVulns.length).toBeGreaterThan(0);
      expect(criticalVulns[0]).toHaveProperty('id');
      expect(criticalVulns[0]).toHaveProperty('cvss');
      expect(criticalVulns[0]).toHaveProperty('summary');
    });
  });

  describe('Vector Store Operations', () => {
    it('should store and retrieve documents', async () => {
      const results = await vectorStore.search({
        query: 'vulnerability',
        k: 5,
      });
      
      expect(results).toHaveLength(5);
      expect(results[0]).toHaveProperty('document');
      expect(results[0]).toHaveProperty('score');
      expect(results[0].document).toHaveProperty('content');
      expect(results[0].document).toHaveProperty('metadata');
    });

    it('should filter by metadata', async () => {
      const results = await vectorStore.search({
        query: 'test',
        filter: { type: 'vulnerability', severity: 'CRITICAL' },
        k: 10,
      });
      
      results.forEach(result => {
        expect(result.document.metadata.type).toBe('vulnerability');
        expect(result.document.metadata.severity).toBe('CRITICAL');
      });
    });
  });

  describe('Agent Q&A Functionality', () => {
    it('should answer critical vulnerability questions', async () => {
      const answer = await agent.ask(
        sbom.projectId,
        'What single upgrade removes the most critical CVEs?'
      );
      
      expect(answer).toBeDefined();
      expect(answer.question).toContain('critical CVEs');
      expect(answer.answerMarkdown).toBeTruthy();
      expect(answer.answerMarkdown.length).toBeGreaterThan(50);
      expect(answer.keyFindings).toBeInstanceOf(Array);
      expect(answer.remediationPlan).toBeInstanceOf(Array);
      expect(answer.remediationPlan.length).toBeGreaterThan(0);
    });

    it('should provide remediation steps with proper structure', async () => {
      const answer = await agent.ask(
        sbom.projectId,
        'What are the most dangerous vulnerabilities?'
      );
      
      expect(answer.remediationPlan).toBeInstanceOf(Array);
      
      if (answer.remediationPlan.length > 0) {
        const step = answer.remediationPlan[0];
        expect(step).toHaveProperty('title');
        expect(step).toHaveProperty('impact');
        expect(step).toHaveProperty('actions');
        expect(step).toHaveProperty('affectedPackages');
        expect(step).toHaveProperty('estimatedBreakage');
        expect(['HIGH', 'MEDIUM', 'LOW']).toContain(step.impact);
        expect(['HIGH', 'MEDIUM', 'LOW']).toContain(step.estimatedBreakage);
      }
    });

    it('should generate appropriate citations', async () => {
      const answer = await agent.ask(
        sbom.projectId,
        'Which packages have the most vulnerabilities?'
      );
      
      expect(answer.citations).toBeInstanceOf(Array);
      expect(answer.citations.length).toBeGreaterThan(0);
      
      const citation = answer.citations[0];
      expect(citation).toHaveProperty('type');
      expect(citation).toHaveProperty('id');
      expect(['package', 'vuln', 'advisory']).toContain(citation.type);
    });
  });

  describe('SBOM Processing', () => {
    it('should process SBOM into searchable documents', () => {
      const processor = new SBOMProcessor();
      const documents = processor.processToDocuments(sbom);
      
      expect(documents.length).toBeGreaterThan(sbom.packages.length);
      
      const projectDoc = documents.find(d => d.id.startsWith('project:'));
      expect(projectDoc).toBeDefined();
      expect(projectDoc!.metadata.type).toBe('project');
      
      const packageDocs = documents.filter(d => d.id.startsWith('package:'));
      expect(packageDocs.length).toBe(sbom.packages.length);
      
      const vulnDocs = documents.filter(d => d.id.startsWith('vuln:'));
      expect(vulnDocs.length).toBeGreaterThan(0);
    });
  });

  describe('Embeddings', () => {
    it('should generate consistent embeddings', async () => {
      const embedder = new MockEmbedder();
      const text = 'test vulnerability';
      
      const embedding1 = await embedder.embed(text);
      const embedding2 = await embedder.embed(text);
      
      expect(embedding1).toEqual(embedding2);
      expect(embedding1).toHaveLength(1536);
      expect(typeof embedding1[0]).toBe('number');
    });

    it('should generate different embeddings for different texts', async () => {
      const embedder = new MockEmbedder();
      
      const embedding1 = await embedder.embed('vulnerability');
      const embedding2 = await embedder.embed('package');
      
      expect(embedding1).not.toEqual(embedding2);
    });
  });

  describe('End-to-End Integration', () => {
    it('should complete full analysis workflow', async () => {
      expect(sbom.summary.counts.critical).toBeGreaterThan(0);
      
      const criticalQuestion = 'What should I do about critical vulnerabilities?';
      const answer = await agent.ask(sbom.projectId, criticalQuestion);
      
      expect(answer).toBeDefined();
      expect(answer.answerMarkdown).toContain('critical');
      expect(answer.remediationPlan.length).toBeGreaterThan(0);
      
      const criticalStep = answer.remediationPlan.find(
        step => step.title.toLowerCase().includes('critical')
      );
      expect(criticalStep).toBeDefined();
      expect(criticalStep!.impact).toBe('HIGH');
    });
  });
});