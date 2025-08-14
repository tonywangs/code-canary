import { 
  createVectorStore, 
  createEmbedder, 
  SBOMProcessor, 
  SecurityAgent 
} from '../index';
import { MockModalClient } from '@dependency-canary/shared';

async function seedMockData() {
  console.log('🌱 Starting mock data seeding...');
  
  try {
    const mockClient = new MockModalClient();
    
    const scanResult = await mockClient.scan({
      projectRef: 'mock-project',
      refType: 'git',
      ref: 'https://github.com/mock/repo',
    });
    
    console.log(`📦 Scan initiated: ${scanResult.jobId}`);
    
    const sbom = await mockClient.enrich(scanResult.jobId);
    console.log(`📊 SBOM generated: ${sbom.packages.length} packages, ${sbom.summary.counts.vulns} vulnerabilities`);
    
    const processor = new SBOMProcessor();
    const documents = processor.processToDocuments(sbom);
    console.log(`📄 Generated ${documents.length} documents for embedding`);
    
    const embedder = createEmbedder();
    console.log('🔗 Creating embeddings...');
    
    for (let i = 0; i < documents.length; i++) {
      const doc = documents[i];
      if (!doc.embedding) {
        doc.embedding = await embedder.embed(doc.content);
      }
      if ((i + 1) % 10 === 0) {
        console.log(`   Embedded ${i + 1}/${documents.length} documents`);
      }
    }
    
    const vectorStore = createVectorStore();
    await vectorStore.clear();
    await vectorStore.addDocuments(documents);
    console.log(`💾 Stored ${documents.length} documents in vector store`);
    
    const agent = new SecurityAgent(vectorStore);
    await agent.indexSBOM(sbom);
    console.log('🤖 Indexed SBOM in security agent');
    
    const testQuestion = "What single upgrade removes the most critical CVEs?";
    console.log(`❓ Testing agent with question: "${testQuestion}"`);
    
    const answer = await agent.ask(sbom.projectId, testQuestion);
    console.log(`✅ Agent responded with ${answer.remediationPlan.length} remediation steps`);
    
    console.log('\n🎉 Mock data seeding completed successfully!');
    console.log('\nTest the system with these sample questions:');
    console.log('- "What single upgrade removes the most critical CVEs?"');
    console.log('- "Which packages pose the highest supply chain risk?"');
    console.log('- "What are the most dangerous vulnerabilities in my direct dependencies?"');
    
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  seedMockData();
}